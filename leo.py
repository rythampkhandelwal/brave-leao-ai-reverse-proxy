#!/usr/bin/env python3
# leo - open-source edition | Built by Cypher Store - https://t.me/Cypherstores_bot
"""
leo - use your Brave Leo Premium subscription from the terminal.

Open-source edition. Built by Cypher Store - https://t.me/Cypherstores_bot

Zero dependencies (stdlib only). Talks directly to the same endpoint the
Brave browser itself uses:

    POST https://ai-chat-premium.bsg.brave.com/v1/chat/completions
    body: {"messages": [...], "model": "claude-opus", "stream": true,
           "brave_capability": []}          (OpenAI-shaped, SSE streamed)

Auth is three parts, all of which belong to *your* install / subscription:

  1. x-brave-key   - static services key baked into your Brave build.
                     Capture it once from your own browser traffic
                     (see README.md - the mitmproxy capture step).
  2. Authorization - HTTP Message Signature (hs2019) over the body digest,
                     HMAC-SHA256 with a pre-shared key baked into your Brave
                     build. `leo find-key` recovers it from your own binary
                     by testing string candidates against a captured
                     signature (no key is shipped with this tool).
  3. Cookie        - __Secure-sku#brave-leo-premium=<credential>. Premium
                     credentials are *single-use* time-limited-v2 tokens,
                     derived locally from a batch Brave downloads into your
                     profile's `Local State` (skus state) after you subscribe.
                     `leo import-batch` copies that batch into leo's own
                     store; every API call then mints a fresh presentation
                     from the next unspent credential, exactly like the
                     browser does (HMAC-SHA512 chain, RFC 9497 finalize).

Setup (once - see README.md and SETUP-macOS.md / SETUP-Windows.md):
    python3 leo.py import-capture   # from a mitmproxy capture (recommended)
    # ... or, step by step:
    python3 leo.py import-batch     # copy the credential batch from Brave
    python3 leo.py find-key --body body.json --signature <captured sig>
    python3 leo.py config --brave-key <captured x-brave-key> --key-id <id>
    python3 leo.py ask "hello"

Use:
    python3 leo.py ask "explain this error"   # one-shot, keeps history
    echo "long text" | python3 leo.py ask "summarise this"
    python3 leo.py chat                       # interactive REPL
    python3 leo.py serve                      # OpenAI-compatible local
                                              # endpoint for opencode /
                                              # aider / scripts
    python3 leo.py --new ask "..."            # fresh session
    python3 leo.py --model claude-sonnet ask ...

    python3 leo.py opencode-config  # register the Leo provider in
                                    # ~/.config/opencode/opencode.json
    python3 leo.py ensure           # credential health check (never signs
                                    # you in automatically; refresh by hand)

Note: Brave rotates (1) and (2) with browser builds and the Premium
credential expires - when you get a 401, re-run import-batch (and, after a
Brave upgrade, find-key). Nothing here bypasses the paywall: no credential,
no Opus. It only spends the subscription you already pay for, from a
terminal instead of a sidebar. Everything stays on your machine: the only
network calls are to Brave's own API, exactly like the browser makes.
"""

import argparse
import base64
import hashlib
import hmac as hmac_mod
import http.client
import http.cookiejar
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

ENDPOINT_PREMIUM = "https://ai-chat-premium.bsg.brave.com/v1/chat/completions"
ENDPOINT_FREE = "https://ai-chat.bsg.brave.com/v1/chat/completions"
COOKIE_NAME = "__Secure-sku#brave-leo-premium"
# When Leo's own backend fails (context too large, provider error), it
# answers HTTP 200 with one of these banners as the reply text instead
# of an error. The bridge converts them back into a real error so agent
# clients retry instead of building on garbage (observed live 2026-10-24).
LEO_ERROR_BANNERS = ("The model returned the following errors:",
                     "There was an issue connecting to the model.")
DEFAULT_MODEL = "claude-opus"   # model *name* sent to the API; the UI key is
                                # "chat-claude-opus". Others: claude-sonnet,
                                # claude-3-haiku, etc. (see README.md)
CHROME_EPOCH_OFFSET = 11644473600  # seconds between 1601-01-01 and 1970-01-01


# ---------------------------------------------------------------- config ---

def config_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    d = base / "leo-cli"
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_config() -> dict:
    p = config_dir() / "config.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def save_config(cfg: dict) -> None:
    p = config_dir() / "config.json"
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        pass


def session_path() -> Path:
    return config_dir() / "session.json"


def load_session() -> list:
    p = session_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def save_session(msgs: list) -> None:
    session_path().write_text(json.dumps(msgs), encoding="utf-8")


# ------------------------------------------- credential minting (v2) ------

def batch_path() -> Path:
    return config_dir() / "batch.json"


def load_batch():
    p = batch_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return None


def save_batch(batch: dict) -> None:
    p = batch_path()
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(batch), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except Exception:
        pass
    tmp.replace(p)


def _finalize_rfc(t: bytes, w: bytes) -> bytes:
    """RFC 9497 finalization (challenge-bypass-ristretto derive key, RFC)."""
    h = hashlib.sha512()
    h.update(len(t).to_bytes(2, "big"))
    h.update(t)
    h.update(len(w).to_bytes(2, "big"))
    h.update(w)
    h.update(b"Finalize")
    return h.digest()


def _presentation(batch: dict, window: dict, cred: dict) -> str:
    raw = base64.b64decode(cred["unblinded_cred"])
    t, w = raw[:64], raw[64:96]
    if cred.get("rfc"):
        vkey = _finalize_rfc(t, w)
    else:
        vkey = hashlib.sha512(b"hash_derive_key" + t + w).digest()
    signature = base64.b64encode(
        hmac_mod.new(vkey, batch["issuer"].encode(), hashlib.sha512).digest()
    ).decode()
    redemption = {
        "validFrom": window["valid_from"],
        "validTo": window["valid_to"],
        "issuer": batch["issuer"],
        "t": base64.b64encode(t).decode(),
        "signature": signature,
    }
    presentation = base64.b64encode(
        json.dumps(redemption, separators=(",", ":")).encode()).decode()
    blob = {"type": "time-limited-v2", "version": 2,
            "sku": batch["sku"], "presentation": presentation}
    cookie = base64.b64encode(
        json.dumps(blob, separators=(",", ":")).encode()).decode()
    # The browser sends this value raw in the Cookie header. Do NOT
    # percent-encode it: the server rejects an encoded value as an
    # invalid credential (40104).
    return cookie


def _window_now(batch: dict):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    usable, fallback = None, None
    for win in batch["windows"]:
        try:
            vf = datetime.fromisoformat(win["valid_from"])
            vt = datetime.fromisoformat(win["valid_to"])
        except Exception:
            continue
        left = sum(1 for c in win["unblinded_creds"] if not c.get("spent"))
        if left == 0:
            continue
        if vf <= now < vt:
            usable = win
            break
        if vt > now and (fallback is None or vf < datetime.fromisoformat(
                fallback["valid_from"])):
            fallback = win
    return usable or fallback


_MINT_LOCK = threading.Lock()


def mint_cookie() -> str:
    """Mint a fresh single-use Premium cookie from the imported batch.

    Marks the credential spent in leo's own store before returning, so a
    crash mid-request can waste at most one credential. Locked: the
    bridge is threaded, and two requests minting the same credential
    would burn one of them on a 40104.
    """
    with _MINT_LOCK:
        return _mint_cookie_locked()


def _mint_cookie_locked() -> str:
    batch = load_batch()
    win = _window_now(batch) if batch else None

    # Auto-reload from Local State if current batch is missing, exhausted, or expired
    if win is None:
        cfg = load_config()
        profile_dir = cfg.get("profile_dir")
        if profile_dir:
            ls = _find_local_state(profile_dir)
            if ls and ls.is_file():
                try:
                    batch = import_batch(ls)
                    win = _window_now(batch)
                except Exception:
                    pass

    if not batch:
        raise LeoError("no credential batch - run `leo import-batch` first "
                       "(see README.md)", 401)
    if win is None:
        raise LeoError("credential batch exhausted or all windows expired - "
                       "open Brave, use Leo once, quit Brave, then re-run "
                       "`leo import-batch`", 401)
    for cred in win["unblinded_creds"]:
        if not cred.get("spent"):
            cred["spent"] = True
            save_batch(batch)
            return _presentation(batch, win, cred)
    raise LeoError("credential window exhausted", 401)


def batch_status_lines(batch: dict) -> list:
    lines = []
    total_left = 0
    for win in batch["windows"]:
        left = sum(1 for c in win["unblinded_creds"] if not c.get("spent"))
        total_left += left
        lines.append(f"  {win['valid_from']} -> {win['valid_to']}: "
                     f"{left}/{len(win['unblinded_creds'])} left")
    lines.append(f"  total unspent: {total_left}")
    return lines


def import_batch(local_state: Path) -> dict:
    """Copy the time-limited-v2 credential batch out of a Brave profile's
    Local State file into leo's own store. Returns the stored batch."""
    data = json.loads(Path(local_state).read_text(encoding="utf-8"))
    state_raw = data["skus"]["state"]
    envs = [k for k in state_raw if k.startswith("skus:")]
    env = "skus:production" if "skus:production" in envs else envs[0]
    st = json.loads(state_raw[env]) if isinstance(state_raw[env], str) \
        else state_raw[env]
    items = st["credentials"]["items"]
    now = datetime.now(timezone.utc).replace(tzinfo=None).isoformat()
    candidates = []
    for item_id, item in items.items():
        windows = item.get("unblinded_creds")
        if not windows:
            continue
        order = None
        sku = None
        for o in (st.get("orders") or {}).values():
            oi = o.get("items")
            cand = oi if isinstance(oi, list) else list((oi or {}).values())
            for it in cand:
                if isinstance(it, dict) and it.get("id") == item_id:
                    order, sku = o, it.get("sku")
        if order is None or not sku:
            continue

        max_vt = max((w.get("valid_to", "") for w in windows), default="")
        has_active = any(w.get("valid_from", "") <= now < w.get("valid_to", "") for w in windows)
        has_future = any(w.get("valid_to", "") > now for w in windows)
        is_leo = (sku == "brave-leo-premium" or "leo" in sku.lower())

        candidates.append({
            "sku": sku,
            "issuer": f'{order["merchant_id"]}?sku={sku}',
            "windows": windows,
            "imported_at": datetime.now(timezone.utc).isoformat(),
            "_score": (is_leo, has_active, has_future, max_vt, item.get("state") == "ActiveCredentials"),
        })

    if not candidates:
        raise SystemExit("no time-limited-v2 credential batch found in that "
                         "Local State - open Leo in Brave once (Premium), quit "
                         "Brave fully, then retry.")

    candidates.sort(key=lambda c: c["_score"], reverse=True)
    batch = candidates[0]
    batch.pop("_score", None)
    save_batch(batch)
    return batch


def _find_local_state(path_input: str | Path) -> Path | None:
    p = Path(path_input).expanduser()
    if p.is_file():
        return p
    for sub in ["", "UserData", "User Data"]:
        cand = (p / sub / "Local State") if sub else (p / "Local State")
        if cand.is_file():
            return cand
    return None


def brave_user_data_candidates() -> list[Path]:
    """Return likely Brave user-data directories on Windows, macOS, and Linux."""
    candidates = []

    if os.name == "nt":
        local = Path(os.environ.get("LOCALAPPDATA", ""))
        roaming = Path(os.environ.get("APPDATA", ""))

        if str(local) not in ("", "."):
            candidates.extend([
                local / "BraveSoftware" / "Brave-Browser" / "User Data",
                local / "BraveSoftware" / "Brave-Browser-Beta" / "User Data",
                local / "BraveSoftware" / "Brave-Browser-Nightly" / "User Data",
            ])

        if str(roaming) not in ("", "."):
            candidates.extend([
                roaming / "BraveSoftware" / "Brave-Browser" / "User Data",
            ])

    elif sys.platform == "darwin":
        candidates.extend([
            Path.home() / "Library" / "Application Support"
            / "BraveSoftware" / "Brave-Browser",
            Path.home() / "Library" / "Application Support"
            / "BraveSoftware" / "Brave-Browser-Beta",
            Path.home() / "Library" / "Application Support"
            / "BraveSoftware" / "Brave-Browser-Nightly",
        ])

    else:
        candidates.extend([
            Path.home() / ".config" / "BraveSoftware" / "Brave-Browser",
            Path.home() / ".config" / "BraveSoftware" / "Brave-Browser-Beta",
            Path.home() / ".config" / "BraveSoftware" / "Brave-Browser-Nightly",
        ])

    # Remove duplicates while preserving order.
    return list(dict.fromkeys(candidates))

def cmd_import_batch(args) -> int:
    ls = None
    if args.local_state:
        ls = _find_local_state(args.local_state)
    elif args.user_data:
        ls = _find_local_state(args.user_data)
    else:
        cfg_profile = load_config().get("profile_dir")
        if cfg_profile:
            ls = _find_local_state(cfg_profile)
        if ls is None:
            for cand in brave_user_data_candidates():
                found = _find_local_state(cand)
                if found:
                    ls = found
                    break
    if ls is None:
        raise SystemExit("Brave profile not found - pass --local-state "
                         "or --user-data.")

    cfg = load_config()
    cfg["profile_dir"] = str(ls.parent)
    save_config(cfg)

    batch = import_batch(ls)
    print(f"imported batch for {batch['sku']} (issuer {batch['issuer']}):")
    for line in batch_status_lines(batch):
        print(line)
    return 0


def cmd_batch(args) -> int:
    batch = load_batch()
    if not batch:
        print("no batch imported yet - run `leo import-batch`.")
        return 1
    print(f"batch for {batch['sku']} (imported {batch.get('imported_at')}):")
    for line in batch_status_lines(batch):
        print(line)
    return 0


def cmd_mint(args) -> int:
    cookie = mint_cookie()
    batch = load_batch()
    left = sum(1 for w in batch["windows"] for c in w["unblinded_creds"]
               if not c.get("spent"))
    print(f"minted one presentation (value not printed); {left} unspent left.")
    return 0


def batch_remaining_current() -> int:
    batch = load_batch()
    win = _window_now(batch) if batch else None
    if win is None:
        cfg = load_config()
        profile_dir = cfg.get("profile_dir")
        if profile_dir:
            ls = _find_local_state(profile_dir)
            if ls and ls.is_file():
                try:
                    batch = import_batch(ls)
                    win = _window_now(batch)
                except Exception:
                    pass
    if win is None:
        return 0
    return sum(1 for c in win["unblinded_creds"] if not c.get("spent"))


def cmd_ensure(args) -> int:
    """Check-only credential health.

    This open-source build never signs you in automatically. If the batch
    runs low, refresh it by hand: open Brave, send Leo one message, quit
    Brave fully, then run `leo import-batch`.
    """
    left = batch_remaining_current()
    if left >= args.min_left:
        if not args.quiet:
            print(f"batch healthy: {left} credentials in current window.")
        return 0
    print(f"batch low ({left} left, want {args.min_left}) - refresh it:")
    print("  1. Open Brave, send Leo one message, quit Brave fully.")
    print("  2. Run: python3 leo.py import-batch")
    return 1


# Every model Leo's API serves, probed live 2026-10-23: all respond, and
# all but GPT Luna make native tool calls. Vision flags follow Leo's own
# model-picker tags. (id, display name, tools, vision, context limit)
LEO_MODELS = [
    ("claude-opus", "Claude Opus — via Leo Premium", True, True, 256000),
    ("claude-sonnet", "Claude Sonnet — via Leo Premium", True, True, 256000),
    ("gpt-5-6-terra-bedrock", "GPT 5.6 Terra — via Leo", True, True, 192000),
    ("grok-4-6-bedrock", "Grok 4.6 — via Leo", True, True, 192000),
    ("qwen", "Qwen 3.5 35B — via Leo", True, True, 192000),
    ("qwen-3-8-flash-next", "Qwen 3.8 Flash Next — via Leo", True, True,
     128000),
    ("deepseek-v3-2", "DeepSeek V3.2 — via Leo", True, False, 128000),
    ("kimi-k2-5", "Kimi K2.5 — via Leo", True, False, 128000),
    ("mistral-large", "Mistral Large 3 — via Leo", True, False, 128000),
    ("nemotron-nano-3-30b", "Nemotron Nano 3 30B — via Leo", True, False,
     128000),
    ("glm-4-7-flash", "GLM 4.7 Flash — via Leo", True, False, 128000),
    ("glm-5-3-flash", "GLM 5.3 Flash — via Leo", True, False, 128000),
    ("gpt-5-6-luna-bedrock", "GPT 5.6 Luna — via Leo (chat only)", False,
     True, 128000),
]


def _provider_models():
    out = {}
    for mid, name, tools, vision, ctx in LEO_MODELS:
        out[mid] = {
            "name": name,
            "capabilities": {
                "tools": tools,
                "input": ["text", "image"] if vision else ["text"],
                "output": ["text"]},
            "limit": {"context": ctx, "output": 8192},
        }
    return out


LEO_PROVIDER_V2 = {
    "name": "Brave Leo Premium (local bridge)",
    "package": "@ai-sdk/openai-compatible",
    "npm": "@ai-sdk/openai-compatible",
    "options": {"baseURL": "http://127.0.0.1:8765/v1", "apiKey": "leo"},
    "settings": {"baseURL": "http://127.0.0.1:8765/v1", "apiKey": "leo"},
    "models": _provider_models(),
}


def install_opencode_config(quiet: bool = False) -> bool:
    """Merge the Leo provider into opencode's global config
    (~/.config/opencode/opencode.json). Idempotent;
    preserves everything else in the file."""
    cdir = Path.home() / ".config" / "opencode"
    target = cdir / "opencode.json"
    target_c = cdir / "opencode.jsonc"
    data = {}
    for p in [target, target_c]:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    break
            except Exception:
                pass
    data.setdefault("$schema", "https://opencode.ai/config.json")
    data.setdefault("model", "leo/claude-opus")
    data.setdefault("provider", {})["leo"] = LEO_PROVIDER_V2
    data.setdefault("providers", {})["leo"] = LEO_PROVIDER_V2
    cdir.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if target_c.exists():
        target_c.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    if not quiet:
        print(f"  Leo provider added to {target}")
    _print_leo_provider_summary()
    return True


def _print_leo_provider_summary():
    """Verification output: what opencode will actually see. If the
    numbers here don't match the app's model picker, the app is
    showing a stale cached config - restart it."""
    print(f"  Leo provider: {len(LEO_MODELS)} models")
    for mid, _name, _tools, _vision, ctx in LEO_MODELS:
        print(f"    leo/{mid}: context {ctx}")


def cmd_opencode_config(args) -> int:
    install_opencode_config(quiet=args.quiet)
    return 0


def _find_or_fetch_mitmdump() -> str:
    """Locate mitmdump, downloading the official standalone build if needed
    (no Homebrew / pip required). Returns a path or ""."""
    found = shutil.which("mitmdump")
    if found:
        return found
    tools = config_dir() / "tools"
    local = tools / "mitmdump"
    if local.exists():
        return str(local)
    if tools.exists():
        for p in tools.rglob("mitmdump"):
            if p.is_file():
                return str(p)
    if sys.platform != "darwin":
        return ""
    arch = "arm64" if platform.machine() == "arm64" else "x86_64"
    ver = "12.3.0"
    url = (f"https://downloads.mitmproxy.org/{ver}/"
           f"mitmproxy-{ver}-macos-{arch}.tar.gz")
    print(f"  downloading mitmproxy standalone ({arch})...")
    try:
        tools.mkdir(parents=True, exist_ok=True)
        tgz = tools / "mitmproxy.tar.gz"
        urllib.request.urlretrieve(url, tgz)
        with tarfile.open(tgz) as tf:
            try:
                tf.extractall(tools, filter="data")
            except TypeError:
                tf.extractall(tools)  # older Pythons (e.g. macOS system 3.9)
        tgz.unlink(missing_ok=True)
        for p in tools.rglob("mitm*"):
            if p.is_file():
                try:
                    p.chmod(0o755)
                except Exception:
                    pass
        for p in tools.rglob("mitmdump"):
            if p.is_file():
                return str(p)
    except Exception as e:
        print(f"  download failed ({e})")
    return ""


# -------------------------------------------------------------- signing -----

def digest_value(body: bytes) -> str:
    return "SHA-256=" + base64.b64encode(hashlib.sha256(body).digest()).decode()


def sign(body: bytes, signing_key: str, key_mode: str) -> str:
    """HTTP Message Signature over `digest` only (Brave's scheme)."""
    msg = f"digest: {digest_value(body)}".encode()
    if key_mode == "hex":
        key = bytes.fromhex(signing_key)
        raw = hmac_mod.new(key, msg, hashlib.sha256).hexdigest()
        return base64.b64encode(bytes.fromhex(raw)).decode()
    key = signing_key.encode()
    return base64.b64encode(hmac_mod.new(key, msg, hashlib.sha256).digest()).decode()


def find_signing_key(body: bytes, target_sig: str, binary):
    """Brute-test string candidates from the Brave binary against a captured
    signature. Returns (key, mode) or None."""
    data = Path(binary).read_bytes()
    candidates = set()
    for m in re.finditer(rb"[0-9a-fA-F]{32,}", data):
        run = m.group().decode()
        candidates.add(run)
        # A key embedded in a longer hex run (adjacent hex bytes) won't be
        # isolated - test every 64-char window too.
        if len(run) > 64:
            for i in range(len(run) - 63):
                candidates.add(run[i:i + 64])
    print(f"testing {len(candidates)} string candidates from {binary} ...")
    for s in candidates:
        for mode in ("hex", "raw"):
            try:
                if sign(body, s, mode) == target_sig:
                    return s, mode
            except Exception:
                continue
    return None


def _binary_candidates(binary):
    """Binaries to scan for the signing key. On macOS the app executable is
    a thin launcher - the real code (and the key) live in the framework
    binary inside the .app bundle."""
    out = [Path(binary)]
    s = str(binary)
    if s.lower().endswith("brave.exe"):
        # On Windows the launcher stub rarely holds the key; the real code
        # lives in chrome.dll inside the versioned Application subfolder.
        parent = Path(binary).parent
        for dll in sorted(parent.glob("*/chrome.dll")):
            out.append(dll)
    if ".app/Contents/MacOS/" in s:
        app = s.split(".app/Contents/")[0] + ".app"
        fw_root = Path(app) / "Contents" / "Frameworks"
        if fw_root.exists():
            for fw in sorted(fw_root.glob("*.framework")):
                cand = fw / "Versions" / "Current" / fw.name.replace(
                    ".framework", "")
                if cand.exists():
                    out.append(cand)
    return out


def cmd_find_key(args) -> int:
    body = Path(args.body).read_bytes()
    binary = Path(args.binary) if args.binary else default_brave_binary()
    if not binary or not Path(binary).exists():
        print("Brave binary not found - pass --binary <path to brave executable>.",
              file=sys.stderr)
        return 1
    found = None
    for cand in _binary_candidates(binary):
        found = find_signing_key(body, args.signature.strip(), cand)
        if found:
            break
    if not found:
        print("No candidate matched. Make sure --body is the *exact* captured "
              "request body and --signature the base64 signature from the same "
              "request's Authorization header.", file=sys.stderr)
        return 1
    key, mode = found
    cfg = load_config()
    cfg["signing_key"], cfg["signing_key_mode"] = key, mode
    if args.key_id:
        cfg["key_id"] = args.key_id
    save_config(cfg)
    print(f"found signing key (mode={mode}) - saved to config.")
    return 0


def cmd_import_capture(args) -> int:
    """One-shot setup from a mitmproxy capture written by capture_addon.py:
    reads body.json + headers.json, stores x-brave-key / keyId, and recovers
    the signing key from the local Brave binary."""
    cap = Path(args.capture_dir)
    headers_file, body_file = cap / "headers.json", cap / "body.json"
    if not headers_file.exists() or not body_file.exists():
        print(f"need {headers_file} and {body_file} - run the capture first "
              "(see README.md).", file=sys.stderr)
        return 1
    raw = json.loads(headers_file.read_text(encoding="utf-8"))
    headers = {k.lower(): v for k, v in raw.items()}
    auth = headers.get("authorization", "")
    m_id = re.search(r'keyId="([^"]+)"', auth)
    m_sig = re.search(r'signature="([^"]+)"', auth)
    if not headers.get("x-brave-key") or not m_id or not m_sig:
        print("capture headers are missing x-brave-key / keyId / signature - "
              "was this the POST to ai-chat-premium.bsg.brave.com?", file=sys.stderr)
        return 1
    cfg = load_config()
    cfg["brave_key"] = headers["x-brave-key"]
    cfg["key_id"] = m_id.group(1)
    save_config(cfg)
    print(f"imported x-brave-key and keyId={cfg['key_id']}")
    binary = Path(args.binary) if args.binary else default_brave_binary()
    if not binary or not Path(binary).exists():
        print("Brave binary not found - pass --binary. Config is saved; "
              "run find-key once the path is known.", file=sys.stderr)
        return 1
    found = None
    for cand in _binary_candidates(binary):
        found = find_signing_key(body_file.read_bytes(), m_sig.group(1), cand)
        if found:
            break
    if not found:
        print("signing key not found from this capture - body/signature "
              "mismatch?", file=sys.stderr)
        return 1
    cfg = load_config()
    cfg["signing_key"], cfg["signing_key_mode"] = found
    save_config(cfg)
    print(f"found signing key (mode={found[1]}) - setup complete. "
          "Now: leo import-batch && leo serve")
    return 0


def default_brave_binary():
    guesses = []
    if os.name == "nt":
        for base in (os.environ.get("PROGRAMFILES", ""), os.environ.get("LOCALAPPDATA", "")):
            guesses += [Path(base) / "BraveSoftware/Brave-Browser/Application/brave.exe"]
    elif sys.platform == "darwin":
        guesses = [
            Path("/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"),
            Path.home() / "Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            Path("/Applications/Brave Browser Beta.app/Contents/MacOS/Brave Browser Beta"),
            Path("/Applications/Brave Browser Nightly.app/Contents/MacOS/Brave Browser Nightly"),
        ]
    else:
        guesses = [Path("/opt/brave.com/brave/brave"), Path("/usr/bin/brave"),
                   Path("/usr/bin/brave-browser")]
    for g in guesses:
        if g and Path(g).exists():
            return g
    return None


# ----------------------------------------------------------------- ask ------

def build_headers(cfg: dict, body: bytes, cookie: str = None):
    missing = [k for k in ("brave_key", "signing_key", "key_id") if not cfg.get(k)]
    if missing:
        raise SystemExit("config missing: " + ", ".join(missing) +
                         " - see README.md setup steps.")
    key_id = cfg["key_id"]
    signature = sign(body, cfg["signing_key"], cfg.get("signing_key_mode", "hex"))
    headers = {
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "x-brave-key": cfg["brave_key"],
        "braveservicekey": cfg["brave_key"],
        "Digest": digest_value(body),
        "Authorization": (f'Signature keyId="{key_id}",algorithm="hs2019",'
                          f'headers="digest",signature="{signature}"'),
    }
    cookie = cookie if cookie is not None else cfg.get("premium_credential")
    if cookie:
        headers["Cookie"] = f"{COOKIE_NAME}={cookie}"
        url = ENDPOINT_PREMIUM
    else:
        url = ENDPOINT_FREE
    return url, headers


def _post_sse(url: str, headers: dict, body: bytes):
    """POST and return the response object (status < 400), streaming.

    Uses http.client directly so HTTPS proxies from the environment are
    honoured via CONNECT with explicit timeouts (urllib's default handling
    can stall on streamed responses behind some proxies).
    """
    parsed = urllib.parse.urlparse(url)
    host, port = parsed.hostname, parsed.port or 443
    proxy = (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
             or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
             or "")
    conn = None
    if proxy:
        p = urllib.parse.urlparse(proxy)
        conn = http.client.HTTPSConnection(p.hostname, p.port or 8080,
                                           timeout=30)
        tunnel_headers = {}
        if p.username:
            cred = f"{urllib.parse.unquote(p.username)}:" \
                   f"{urllib.parse.unquote(p.password or '')}"
            tunnel_headers["Proxy-Authorization"] = "Basic " + base64.b64encode(
                cred.encode()).decode()
        conn.set_tunnel(host, port, headers=tunnel_headers)
    else:
        conn = http.client.HTTPSConnection(host, port, timeout=30)
    conn.request("POST", parsed.path or "/", body=body, headers=headers)
    # Leo can take a while to answer a very large prompt before sending
    # headers; the short connect timeout must not apply to that wait.
    if conn.sock is not None:
        conn.sock.settimeout(300)
    resp = conn.getresponse()
    if resp.status >= 400:
        detail = resp.read().decode(errors="replace")[:400]
        conn.close()
        hint = ""
        if resp.status == 401:
            hint = "\n-> 401: credential/key rejected. Re-import the batch " \
                   "(`leo import-batch`); after a Brave upgrade also re-run " \
                   "the capture/import."
        elif resp.status == 429:
            hint = "\n-> 429: Leo's per-model premium rate limit (it is " \
                   "high, not literally unlimited). Wait, or use " \
                   "claude-sonnet."
        raise LeoError(f"Leo API {resp.status}: {detail}{hint}", resp.status)
    if conn.sock is not None:
        conn.sock.settimeout(300)
    return resp


def leo_chunks(messages: list, model: str, cfg: dict, tools=None,
               extra=None):
    """Generator yielding raw parsed SSE chunk dicts from Leo.

    With an imported credential batch, each attempt mints a fresh
    single-use presentation; a 40104 (credential already spent - e.g. the
    browser spent it first) retries with the next credential. `extra`
    carries optional OpenAI fields Leo accepts (e.g. temperature);
    max_tokens and tool_choice are NOT forwarded - Leo provably ignores
    them (verified 2026-10-24).
    """
    payload = {"messages": messages, "model": model, "stream": True,
               "brave_capability": []}
    if tools:
        payload["tools"] = tools
    if extra:
        payload.update(extra)
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    use_batch = load_batch() is not None
    attempts = 3 if use_batch else 1
    for attempt in range(attempts):
        cookie = mint_cookie() if use_batch else None
        url, headers = build_headers(cfg, body, cookie)
        try:
            resp = _post_sse(url, headers, body)
        except LeoError as e:
            if use_batch and attempt + 1 < attempts and "40104" in str(e):
                continue
            raise
        for raw in resp:
            line = raw.decode(errors="replace").strip()
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                break
            try:
                yield json.loads(data)
            except Exception:
                continue
        return


class LeoError(Exception):
    def __init__(self, msg, code=502):
        super().__init__(msg)
        self.code = code


def stream_completion(messages: list, model: str, cfg: dict):
    """Generator yielding text deltas from Leo's SSE stream."""
    for chunk in leo_chunks(messages, model, cfg):
        yield from chunk_text(chunk)


def chunk_text(chunk: dict):
    """OpenAI chunk shape, plus Brave's completion-event fallback."""
    for choice in chunk.get("choices") or []:
        delta = choice.get("delta") or {}
        if delta.get("content"):
            yield delta["content"]
        elif choice.get("text"):
            yield choice["text"]
    if isinstance(chunk.get("completion"), str):
        yield chunk["completion"]


def run_ask(prompt: str, model: str, system: str, fresh: bool) -> str:
    cfg = load_config()
    history = [] if fresh else load_session()
    msgs = list(history)
    if system and not any(m.get("role") == "system" for m in msgs):
        msgs.insert(0, {"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    out = []
    try:
        for delta in stream_completion(msgs, model, cfg):
            sys.stdout.write(delta)
            sys.stdout.flush()
            out.append(delta)
    except LeoError as e:
        raise SystemExit(str(e))
    print()
    answer = "".join(out)
    save_session(msgs + [{"role": "assistant", "content": answer}])
    return answer


def cmd_chat(args) -> int:
    print("Leo (Ctrl-C to exit, /new for a fresh session, /model <name>)")
    model, system = args.model, args.system
    while True:
        try:
            prompt = input("\n> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not prompt:
            continue
        if prompt == "/new":
            save_session([])
            print("(fresh session)")
            continue
        if prompt.startswith("/model "):
            model = prompt.split(None, 1)[1].strip()
            print(f"(model: {model})")
            continue
        run_ask(prompt, model, system, fresh=False)


# ---------------------------------------------------------------- serve -----
# OpenAI-compatible bridge for opencode (and aider etc).
#
# Tools: Leo's endpoint is an OpenAI-shaped API and its client parses
# choices[0].delta.tool_calls, so "native" mode forwards opencode's tools
# straight through. Leo's UI metadata marks Opus supports_tools=false
# though - if Opus answers in prose instead of calling tools, switch to
# "prompt" mode (leo config --tools-mode prompt, or LEO_TOOLS=prompt):
# the bridge then teaches the model a <tool_call> text format, parses it
# back out, and synthesises real OpenAI tool_calls for opencode.

TOOL_INSTRUCTIONS = """

# Tool calling
You have access to the tools listed below. When you need a tool, respond \
with ONLY one or more blocks in exactly this format, and no other text:

<tool_call>
{"name": "<tool name>", "arguments": {<arguments as a JSON object>}}
</tool_call>

Rules:
- The arguments value must be a single valid JSON object matching the \
tool's parameter schema.
- You may emit several <tool_call> blocks in one reply.
- After tool results are returned to you, continue the task; call more \
tools or give the final answer as plain text (no <tool_call> block).
- Never invent a tool result. If no tool is needed, answer in plain text.

## Available tools
"""

_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.S)


def normalize_model(name: str) -> str:
    name = (name or DEFAULT_MODEL).strip()
    if "/" in name:
        name = name.rsplit("/", 1)[-1]
    if name.startswith("chat-claude"):
        name = name[len("chat-"):]
    return name


def _text_of(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for p in content:
            if isinstance(p, dict) and p.get("type") in ("text", "input_text"):
                parts.append(p.get("text", ""))
            elif isinstance(p, str):
                parts.append(p)
        return "".join(parts)
    return "" if content is None else str(content)


_IMG_CACHE = {}


def _inline_image(url: str):
    """Leo only accepts image attachments as inline data URLs - fetch a
    remote image and return a data: URL (None on failure)."""
    if url in _IMG_CACHE:
        return _IMG_CACHE[url]
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (leo-bridge)"})
        with urllib.request.urlopen(req, timeout=15) as r:
            blob = r.read(10 * 1024 * 1024 + 1)
            ctype = r.headers.get_content_type() or "image/png"
        if len(blob) > 10 * 1024 * 1024:
            return None
        out = (f"data:{ctype};base64,"
               + base64.b64encode(blob).decode())
        _IMG_CACHE[url] = out
        return out
    except Exception:
        return None


def _sanitize_parts(content):
    """Make a content-part list safe for Leo. Leo's API rejects any part
    type it doesn't know (400 'Input should be a valid string') - and
    opencode v2 legitimately sends reasoning/thinking parts (assistant
    history) and file parts (attachments). Map what we can, drop the
    rest:
      text/input_text -> kept; image_url -> kept (remote URLs inlined);
      file (data URL) -> decoded text part when textual, else a note;
      reasoning/thinking/anything else -> dropped."""
    out = []
    for p in content:
        if not isinstance(p, dict):
            out.append({"type": "text", "text": str(p)})
            continue
        t = p.get("type")
        if t in ("text", "input_text"):
            out.append({"type": "text", "text": p.get("text", "")})
        elif t == "image_url":
            iu = p.get("image_url") or {}
            url = iu.get("url", "")
            if url.startswith(("http://", "https://")):
                data_url = _inline_image(url)
                if data_url:
                    out.append({**p, "image_url": {**iu, "url": data_url}})
                else:
                    out.append({"type": "text",
                                "text": "[an image was attached but "
                                        "could not be loaded]"})
            else:
                out.append(p)
        elif t == "file":
            name = p.get("filename") or "file"
            url = p.get("url") or ""
            mime = p.get("mime") or ""
            text = None
            if url.startswith("data:") and ";base64," in url:
                try:
                    raw = base64.b64decode(url.split(",", 1)[1])
                    if mime.startswith("text/") or len(raw) < 200_000:
                        text = raw.decode("utf-8", errors="strict")
                except Exception:
                    text = None
            if text is not None:
                out.append({"type": "text",
                            "text": f"[file: {name}]\n{text}"})
            else:
                out.append({"type": "text",
                            "text": f"[a file was attached: {name}]"})
        elif t in ("reasoning", "thinking", "redacted_thinking",
                   "reasoning_text"):
            continue  # model scratchpad - Leo rejects it; safe to drop
        elif isinstance(p.get("text"), str):
            out.append({"type": "text", "text": p["text"]})
        # anything else: drop rather than poison the whole request
    return out


def flatten_native(messages: list) -> list:
    out = []
    for m in messages:
        nm = {"role": m.get("role", "user")}
        c = m.get("content")
        if isinstance(c, list):
            c = _sanitize_parts(c)
            if not c:
                c = ""
        nm["content"] = c if isinstance(c, (str, list)) else _text_of(c)
        if isinstance(nm["content"], list) and all(
                isinstance(p, dict) and p.get("type") == "text"
                for p in nm["content"]):
            nm["content"] = _text_of(nm["content"])
        if m.get("tool_calls"):
            nm["tool_calls"] = m["tool_calls"]
        if m.get("tool_call_id"):
            nm["tool_call_id"] = m["tool_call_id"]
        if m.get("name"):
            nm["name"] = m["name"]
        out.append(nm)
    return out


def flatten_prompt(messages: list, tools: list) -> list:
    """Render an opencode conversation as plain text messages + a tool
    manual in the system prompt, for prompt-mode tool emulation."""
    specs = []
    for t in tools:
        fn = t.get("function") or t
        specs.append(f"### {fn.get('name')}\n{fn.get('description', '')}\n"
                     f"Parameters (JSON schema): "
                     f"{json.dumps(fn.get('parameters') or {})}")
    manual = TOOL_INSTRUCTIONS + "\n\n".join(specs)
    id_to_name = {}
    for m in messages:
        for tc in m.get("tool_calls") or []:
            fn = tc.get("function") or {}
            if tc.get("id"):
                id_to_name[tc["id"]] = fn.get("name", "tool")
    out, system_parts = [], []
    for m in messages:
        role, text = m.get("role"), _text_of(m.get("content"))
        if role == "system":
            system_parts.append(text)
        elif role == "assistant":
            blocks = []
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                blocks.append("<tool_call>\n" + json.dumps(
                    {"name": fn.get("name"),
                     "arguments": _json_obj(fn.get("arguments"))}) +
                    "\n</tool_call>")
            joined = "\n".join(([text] if text else []) + blocks)
            out.append({"role": "assistant", "content": joined})
        elif role == "tool":
            name = id_to_name.get(m.get("tool_call_id"), "tool")
            out.append({"role": "user",
                        "content": f"[Tool result from {name}]\n{text}"})
        else:
            out.append({"role": role or "user", "content": text})
    system = "\n\n".join(p for p in system_parts if p)
    out.insert(0, {"role": "system",
                   "content": (system + "\n" + manual) if system else manual})
    return out


def _json_obj(v):
    if isinstance(v, dict):
        return v
    try:
        return json.loads(v)
    except Exception:
        return {}


def parse_tool_calls(text: str):
    """-> (clean_text, [openai tool_call dicts])"""
    calls = []
    for i, m in enumerate(_TOOL_CALL_RE.finditer(text or "")):
        try:
            obj = json.loads(m.group(1))
        except Exception:
            continue
        if not obj.get("name"):
            continue
        calls.append({"id": f"call_{i}",
                      "type": "function",
                      "function": {"name": obj["name"],
                                    "arguments": json.dumps(
                                        obj.get("arguments") or {})}})
    clean = _TOOL_CALL_RE.sub("", text or "").strip()
    return clean, calls


def _agg_native(chunks):
    """Aggregate a native Leo stream -> (text, tool_calls, finish_reason,
    usage)"""
    text, by_index, finish, usage = [], {}, None, None
    for chunk in chunks:
        if chunk.get("usage"):
            usage = chunk["usage"]
        for choice in chunk.get("choices") or []:
            delta = choice.get("delta") or choice.get("message") or {}
            if delta.get("content"):
                text.append(delta["content"])
            for tc in delta.get("tool_calls") or []:
                idx = tc.get("index", 0)
                cur = by_index.setdefault(idx, {
                    "id": tc.get("id") or f"call_{idx}", "type": "function",
                    "function": {"name": "", "arguments": ""}})
                fn = tc.get("function") or {}
                if tc.get("id"):
                    cur["id"] = tc["id"]
                cur["function"]["name"] += fn.get("name") or ""
                cur["function"]["arguments"] += fn.get("arguments") or ""
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
    calls = [by_index[k] for k in sorted(by_index)]
    if calls and finish in (None, "stop"):
        finish = "tool_calls"
    joined = "".join(text)
    if not calls and joined.startswith(LEO_ERROR_BANNERS):
        raise LeoError(f"Leo upstream failure: {joined[:240]}", 502)
    return joined, calls, finish or "stop", usage


def cmd_serve(args) -> int:
    """OpenAI-compatible bridge on http://127.0.0.1:<port>/v1
    Point opencode at it with the shipped opencode.json (provider 'leo')."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    cfg = load_config()
    tools_mode = (getattr(args, "tools_mode", "") or
                  os.environ.get("LEO_TOOLS") or
                  cfg.get("tools_mode") or "native")
    api_key = (getattr(args, "api_key", "") or
               os.environ.get("LEO_BRIDGE_KEY") or
               cfg.get("bridge_key") or "")
    cid = [0]

    def next_id():
        cid[0] += 1
        return f"chatcmpl-leo-{cid[0]}"

    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _json(self, code, obj):
            blob = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def _err(self, code, msg):
            self._json(code, {"error": {"message": str(msg),
                                         "type": "leo_bridge_error"}})

        def _authorized(self):
            if not api_key:
                return True
            return self.headers.get("Authorization") == f"Bearer {api_key}"

        def do_GET(self):
            if not self._authorized():
                self._err(401, "unauthorized")
                return
            if self.path.rstrip("/").endswith("/models"):
                now = int(time.time())
                ids = [m[0] for m in LEO_MODELS] + ["claude-3-haiku"]
                self._json(200, {"object": "list", "data": [
                    {"id": m, "object": "model", "created": now,
                     "owned_by": "leo"}
                    for m in ids]})
            elif self.path in ("/", "/health"):
                self._json(200, {"status": "ok", "tools_mode": tools_mode})
            else:
                self._err(404, "not found")

        def do_POST(self):
            if not self._authorized():
                self._err(401, "unauthorized")
                return
            if not self.path.rstrip("/").endswith("/chat/completions"):
                self._err(404, "not found")
                return
            n = int(self.headers.get("Content-Length", 0))
            try:
                req = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                self._err(400, "bad json")
                return
            model = normalize_model(req.get("model"))
            tools = req.get("tools") or []
            want_stream = bool(req.get("stream"))
            temp = req.get("temperature")
            extra = {"temperature": temp} \
                if isinstance(temp, (int, float)) else None
            mode = "prompt" if (tools and tools_mode == "prompt") else "native"
            print(f"[leo] {model} mode={mode} tools={len(tools)} "
                  f"stream={want_stream} msgs={len(req.get('messages') or [])}",
                  file=sys.stderr)
            try:
                if mode == "prompt":
                    msgs = flatten_prompt(req.get("messages") or [], tools)
                    text_parts = []
                    for ch in leo_chunks(msgs, model, cfg, extra=extra):
                        text_parts.extend(chunk_text(ch))
                    clean, calls = parse_tool_calls("".join(text_parts))
                    if not calls and clean.startswith(LEO_ERROR_BANNERS):
                        raise LeoError(
                            f"Leo upstream failure: {clean[:240]}", 502)
                    self._reply(req, model, want_stream, clean, calls,
                                "tool_calls" if calls else "stop", next_id())
                elif want_stream:
                    self._stream_native(req, model, tools, next_id(), extra)
                else:
                    msgs = flatten_native(req.get("messages") or [])
                    text, calls, finish, usage = _agg_native(
                        leo_chunks(msgs, model, cfg, tools or None,
                                   extra=extra))
                    self._reply(req, model, False, text, calls, finish,
                                next_id(), usage=usage)
            except LeoError as e:
                # Pass 4xx through so clients can react properly (bad
                # request vs rate limit vs auth); the rest is a
                # bridge-side 502.
                self._err(e.code if 400 <= e.code < 500 else 502, e)
            except (TimeoutError, http.client.HTTPException) as e:
                # Upstream stall: answer with an error instead of
                # dropping the connection (a dropped stream surfaces in
                # opencode as "stream ended without finish_reason").
                try:
                    self._err(504, f"Leo request timed out: {e}")
                except Exception:
                    pass
            except (BrokenPipeError, ConnectionResetError):
                pass

        # -- helpers -----------------------------------------------------
        def _reply(self, req, model, want_stream, text, calls, finish, rid,
                   usage=None):
            if want_stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                self.close_connection = True
                chunks = []
                if text:
                    chunks.append({"role": "assistant", "content": text})
                if calls:
                    chunks.append({"role": "assistant", "tool_calls": [
                        {**tc, "index": i} for i, tc in enumerate(calls)]})
                if not chunks:
                    chunks.append({"role": "assistant", "content": ""})
                for d in chunks:
                    self._sse(rid, model, d, None)
                self._sse(rid, model, {}, finish)
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            else:
                msg = {"role": "assistant", "content": text or None}
                if calls:
                    msg["tool_calls"] = calls
                self._json(200, {
                    "id": rid, "object": "chat.completion",
                    "created": int(time.time()), "model": model,
                    "choices": [{"index": 0, "message": msg,
                                 "finish_reason": finish}],
                    "usage": usage or {"prompt_tokens": 0,
                                       "completion_tokens": 0,
                                       "total_tokens": 0}})

        def _sse(self, rid, model, delta, finish):
            chunk = {"id": rid, "object": "chat.completion.chunk",
                     "created": int(time.time()), "model": model,
                     "choices": [{"index": 0, "delta": delta,
                                  "finish_reason": finish}]}
            self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode())
            self.wfile.flush()

        def _stream_native(self, req, model, tools, rid, extra=None):
            msgs = flatten_native(req.get("messages") or [])
            gen = leo_chunks(msgs, model, cfg, tools or None, extra=extra)
            want_usage = bool((req.get("stream_options") or {})
                              .get("include_usage"))
            # Prime the generator BEFORE sending headers: if Leo refuses
            # the request up front (rate limit, bad request, no
            # credentials), the LeoError propagates to do_POST and the
            # client gets a real HTTP error it can react to - not a fake
            # "successful" stream containing error text. Priming also
            # watches the first content for Leo's failure banner (its
            # backend reports some failures as HTTP-200 reply text).
            it = iter(gen)
            primed = []
            probe_text = ""
            try:
                while True:
                    chunk = next(it)
                    primed.append(chunk)
                    decided = False
                    for choice in chunk.get("choices") or []:
                        delta = choice.get("delta") or {}
                        if delta.get("tool_calls") or \
                                choice.get("finish_reason"):
                            decided = True
                        probe_text += delta.get("content") or ""
                    if decided or len(probe_text) >= 64:
                        break
            except StopIteration:
                pass
            if probe_text.startswith(LEO_ERROR_BANNERS):
                raise LeoError(
                    f"Leo upstream failure: {probe_text[:240]}", 502)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            saw_tool, first, finished = False, True, False
            failed = False
            pending_usage = None
            # Leo delivers text in bursts (a long pause, then a whole
            # paragraph at once) - that reads as choppy next to native
            # Opus. Pace large text deltas into word-sized pieces so
            # the client renders progressively. Bounded: at most ~2s of
            # pacing per response, tool deltas never paced (they gate
            # execution, not display).
            pace_left = [2.0]

            def emit(delta, finish):
                text = delta.get("content") or ""
                if (not delta.get("tool_calls") and len(text) > 80
                        and pace_left[0] > 0):
                    pieces = re.findall(r"\S{1,40}\s*|\s+", text)
                    role = delta.get("role")
                    for i, piece in enumerate(pieces):
                        last = i == len(pieces) - 1
                        d = {"content": piece}
                        if i == 0 and role:
                            d = {"role": role, **d}
                        self._sse(rid, model, d, finish if last else None)
                        if not last and pace_left[0] > 0:
                            time.sleep(0.015)
                            pace_left[0] -= 0.015
                else:
                    self._sse(rid, model, delta, finish)

            def _events():
                yield from primed
                yield from it

            try:
                for chunk in _events():
                    if chunk.get("usage"):
                        pending_usage = chunk["usage"]
                    for choice in chunk.get("choices") or []:
                        delta = choice.get("delta") or {}
                        if delta.get("tool_calls"):
                            saw_tool = True
                        if first and "role" not in delta:
                            delta = {"role": "assistant", **delta}
                        first = False
                        finish = choice.get("finish_reason")
                        if finish and saw_tool and finish == "stop":
                            finish = "tool_calls"
                        if finished:
                            # Leo sometimes sends an empty trailing chunk
                            # AFTER the finish chunk. Strict clients treat
                            # anything after finish_reason as corruption -
                            # drop empties; real content reopens the stream
                            # and gets closed again at the end.
                            if not delta.get("content") and \
                                    not delta.get("tool_calls"):
                                continue
                            finished = False
                            finish = None
                        if finish:
                            finished = True
                        emit(delta, finish)
            except LeoError as e:
                # Mid-stream upstream failure: end WITHOUT a finish
                # chunk. The client treats that as a failed stream and
                # retries the step; faking a "stop" plus error text
                # would silently corrupt an agent's work.
                print(f"[leo] mid-stream error: {e}", file=sys.stderr)
                failed = True
            if not finished and not failed:
                # Leo's stream can also end with [DONE] only, never naming
                # a finish_reason - strict OpenAI clients (opencode v2)
                # reject that and retry. Always close with one.
                self._sse(rid, model, {},
                          "tool_calls" if saw_tool else "stop")
            if want_usage and pending_usage and not failed:
                # OpenAI shape for the usage report: after the finish
                # chunk, one chunk with empty choices, before [DONE].
                uchunk = {"id": rid, "object": "chat.completion.chunk",
                          "created": int(time.time()), "model": model,
                          "choices": [], "usage": pending_usage}
                self.wfile.write(
                    f"data: {json.dumps(uchunk)}\n\n".encode())
                self.wfile.flush()
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

    print(f"leo bridge: http://127.0.0.1:{args.port}/v1  "
          f"(tools mode: {tools_mode})", flush=True)
    print("  opencode: use the shipped opencode.json, model leo/claude-opus",
          flush=True)
    print("  built by Cypher Store - https://t.me/Cypherstores_bot",
          flush=True)
    ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()
    return 0


# ------------------------------------------------------------------ main ----

def main() -> int:
    ap = argparse.ArgumentParser(prog="leo", description=__doc__.splitlines()[1])
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--system", default="")
    ap.add_argument("--new", action="store_true", help="fresh session")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("ask"); p.add_argument("prompt", nargs="*")
    sub.add_parser("chat")
    p = sub.add_parser("find-key")
    p.add_argument("--binary", default=""); p.add_argument("--body", required=True)
    p.add_argument("--signature", required=True); p.add_argument("--key-id", default="")
    p = sub.add_parser("config")
    p.add_argument("--brave-key", default=""); p.add_argument("--key-id", default="")
    p.add_argument("--tools-mode", default="", choices=["", "native", "prompt"])
    p.add_argument("--profile-dir", default="")
    p = sub.add_parser("import-capture")
    p.add_argument("capture_dir", nargs="?", default="~/leo-capture")
    p.add_argument("--binary", default="")
    p = sub.add_parser("serve"); p.add_argument("--port", type=int, default=8765)
    p.add_argument("--tools-mode", default="", choices=["", "native", "prompt"])
    p.add_argument("--api-key", default="",
                   help="require this Bearer key on bridge requests")
    p = sub.add_parser("import-batch")
    p.add_argument("--local-state", default="")
    p.add_argument("--user-data", default="")
    sub.add_parser("batch")
    sub.add_parser("mint")
    p = sub.add_parser("ensure")
    p.add_argument("--min-left", type=int, default=30)
    p.add_argument("--quiet", action="store_true")
    p = sub.add_parser("opencode-config")
    p.add_argument("--quiet", action="store_true")

    args = ap.parse_args()

    if args.cmd == "find-key":
        return cmd_find_key(args)
    if args.cmd == "import-capture":
        args.capture_dir = os.path.expanduser(args.capture_dir)
        return cmd_import_capture(args)
    if args.cmd == "config":
        cfg = load_config()
        if args.brave_key:
            cfg["brave_key"] = args.brave_key
        if args.key_id:
            cfg["key_id"] = args.key_id
        if args.tools_mode:
            cfg["tools_mode"] = args.tools_mode
        if args.profile_dir:
            cfg["profile_dir"] = args.profile_dir
        save_config(cfg)
        print("saved:", {k: ("<set>" if k in ("brave_key", "signing_key",
               "premium_credential") and v else v) for k, v in cfg.items()})
        return 0
    if args.cmd == "import-batch":
        return cmd_import_batch(args)
    if args.cmd == "batch":
        return cmd_batch(args)
    if args.cmd == "mint":
        return cmd_mint(args)
    if args.cmd == "ensure":
        return cmd_ensure(args)
    if args.cmd == "opencode-config":
        return cmd_opencode_config(args)
    if args.cmd == "serve":
        return cmd_serve(args)
    if args.cmd == "chat":
        return cmd_chat(args)
    # default / ask
    prompt = " ".join(getattr(args, "prompt", []) or [])
    if not sys.stdin.isatty():
        # Read piped stdin only if data is actually available, so running
        # under a supervisor/cron with an open but silent stdin can't hang.
        try:
            import select
            ready, _, _ = select.select([sys.stdin], [], [], 0.3)
        except Exception:
            ready = [sys.stdin]
        piped = sys.stdin.read() if ready else ""
        prompt = f"{prompt}\n\n{piped}".strip() if prompt else piped.strip()
    if not prompt:
        ap.print_help()
        return 1
    run_ask(prompt, args.model, args.system, fresh=args.new)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
