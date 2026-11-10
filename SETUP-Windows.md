# Setup guide — Windows
>
> Works with plain Windows (no WSL needed for leo itself). Time:
> ~15 minutes, most of it waiting on Brave.

## 0. What you need

- Brave Browser installed, signed in, with an **active Leo Premium**
  subscription (open Brave, ask Leo anything — it must answer as Premium).
- Python 3.9+ from [python.org/downloads](https://www.python.org/downloads/).
  **Tick "Add python.exe to PATH"** during install. Check with
  `py -3 --version` in PowerShell or Command Prompt.
- This folder (`leo.py`, `capture_addon.py`, `opencode.json`) somewhere
  stable, e.g. `C:\Users\<you>\leo\`.
- opencode — the [desktop app](https://opencode.ai) (simplest with
  `leo-bridge.bat`), or the TUI via
  `scoop install opencode` / `choco install opencode`, or inside WSL —
  only if you want the agent workflow. `leo ask` works without it.

In the commands below, `py -3 leo.py ...` is used; if `py` isn't on your
machine, use `python leo.py ...` instead. The `.bat` launchers in this
folder try `py` first and fall back to `python` automatically.

## 1. Install mitmproxy (one-time capture tool)

```powershell
py -3 -m pip install mitmproxy
```

This is only used once, to capture a single genuine Leo request from
your own browser — nothing else.

## 2. Trust mitmproxy's certificate (one time)

Brave won't let a proxy read its HTTPS traffic until you trust mitmproxy's
local CA certificate:

```powershell
mitmdump -s capture_addon.py
```

Leave that window running, then in a browser *without* the proxy for a
moment, open http://mitm.it, download the **Windows** certificate, and
install it into **Trusted Root Certification Authorities** (double-click
the `.cer` → Install Certificate → Local Machine → "Place all
certificates in the following store" → Trusted Root Certification
Authorities). Then continue in the mitmdump window.

(You can remove this certificate later from `certmgr.msc` once setup is
done.)

## 3. Capture ONE Leo request

Quit Brave completely first (right-click its tray icon → Exit, or close
all windows and check Task Manager — Brave must not be running), then
relaunch it *through the proxy* from PowerShell:

```powershell
& "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe" --proxy-server=http://127.0.0.1:8080
```

(If Brave lives elsewhere, adjust the path; the flag is the important
part.)

In that Brave window: open the Leo sidebar, select **Claude Opus**, send
any short message ("hello"). The mitmdump window should print:

```
[leo-capture] saved Leo request to C:\Users\<you>\leo-capture - you can Ctrl-C mitmdump now
```

Stop mitmdump (Ctrl-C in its window) and **quit Brave fully**.
From now on, launch Brave normally — the proxy flag was only for this
capture.

What was saved (in `%USERPROFILE%\leo-capture\`):

- `body.json` — the exact request body (ground truth for key recovery).
- `headers.json` — its headers: `x-brave-key`, `keyId`, and the
  `Authorization` signature.

**Alternative without mitmproxy (advanced):** capture the same POST to
`ai-chat-premium.bsg.brave.com/v1/chat/completions` in Brave's devtools
Network panel, save the raw request body as `body.json` and a
`headers.json` containing `x-brave-key` and the full `authorization`
header value, then continue at step 4. The file layout is what
`import-capture` reads, however you produced it.

## 4. Import the capture (key, keyId, signing key)

```powershell
cd C:\Users\<you>\leo
py -3 leo.py import-capture
```

This stores `x-brave-key` and `keyId` in leo's config and recovers the
signing key from your Brave binary. On Windows the key is usually in
`chrome.dll` inside the versioned Application folder rather than in
`brave.exe` itself — `import-capture` now scans both automatically
(`brave.exe` first, then `chrome.dll` next to it). Expected output ends
with the signing key saved.

If it reports the binary wasn't found, pass it explicitly:

```powershell
py -3 leo.py import-capture --binary "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
```

## 5. Import the credential batch

```powershell
py -3 leo.py import-batch
```

This copies the Premium credential batch from your Brave profile's
`Local State` into leo's store. leo looks in
`%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data` (plus Beta and
Nightly variants) automatically. Expected output lists the batch with a
healthy number of unspent credentials.

If it finds nothing:

1. Open Brave normally, send Leo a message.
2. Go to account.brave.com, wait for the subscriptions section to render,
   click **Refresh Leo AI**.
3. Quit Brave completely (so `Local State` flushes).
4. Run `import-batch` again.

You can also point at a profile explicitly:

```powershell
py -3 leo.py import-batch --user-data "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
```

## 6. Check, register opencode, go

```powershell
py -3 leo.py ensure
py -3 leo.py opencode-config
```

`opencode-config` prints the provider it wrote — check it lists
**13 models** (Opus/Sonnet at 256,000 context). It writes into
`%USERPROFILE%\.config\opencode\opencode.json` and leaves everything
else in that file alone; it sets Leo as the default model only if you
had none.

Then start the bridge and leave its window open:

```powershell
py -3 leo.py serve
```

(or double-click `leo-bridge.bat` in this folder — same thing, and
`leo-opencode.bat` runs the health check plus the bridge together.)

Open the opencode desktop app (or TUI), start a **new chat**, pick a
`leo/...` model. If the model list looks stale, fully quit the app
(right-click its tray/Dock icon → Quit, not just closing the window)
and reopen it — it caches the provider list at launch. If it *still*
shows old models, check for an `opencode.json` in your project folder:
project configs override the global one.

## 7. Clean up

```powershell
Remove-Item -Recurse -Force $env:USERPROFILE\leo-capture
```

That folder held one captured request. Optionally also remove the
mitmproxy CA from `certmgr.msc`. Keep `leo.py`'s config where it is —
it holds your batch and keys (local only).

## 8. Day to day

- Start the bridge before opencode: double-click `leo-bridge.bat`, or
  `py -3 leo.py serve`.
- `py -3 leo.py ensure` — batch health. When it reports low, refresh by
  hand: Brave → Leo message → quit Brave → `py -3 leo.py import-batch`.
- `401` after a Brave upgrade → repeat steps 3–4 (keys rotate with
  builds), then `import-batch` again.
- `429` → that model's daily bucket is drained; switch models or wait
  for 00:00 UTC.

## Windows notes

- leo's config and batch live under `%APPDATA%` on Windows (the same
  relative layout as other platforms' config dirs).
- Windows Defender SmartScreen may flag the `.bat` files on first run
  (they're plain text — right-click → Edit to inspect them, then
  "Run anyway" if you're happy). No admin rights are needed anywhere in
  this guide except the one-time certificate install in step 2.
- If you prefer WSL: everything above works inside WSL too, except the
  Brave profile path becomes the Windows one — pass it with
  `--user-data /mnt/c/Users/<you>/AppData/Local/BraveSoftware/Brave-Browser/User Data`
  and point `find-key`/`import-capture` at the Windows Brave binary the
  same way.
