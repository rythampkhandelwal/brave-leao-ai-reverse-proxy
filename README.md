# leo — Brave Leo Premium, outside the browser

Use your **Brave Leo Premium** subscription from the terminal and from
[opencode](https://opencode.ai) — every Leo model, including Claude Opus —
instead of only inside Brave's sidebar.

`leo` is a zero-dependency Python program (standard library only). It talks
directly to the same endpoint Brave itself uses:

```
POST https://ai-chat-premium.bsg.brave.com/v1/chat/completions
```

and it can serve a local OpenAI-compatible endpoint (`leo serve`) that
opencode points at, so the models behave like any other opencode provider:
chat, tools, streaming, file edits, shell commands, multi-step agent work.

**Nothing here bypasses the paywall.** It only spends the subscription you
already pay for, from a terminal instead of a sidebar. No credential, no
Opus — and no account farming, no shared accounts, no trial abuse. One
person, one paid subscription, their own machine.

## How it works

Brave's Premium API authenticates each request with three things, all of
which belong to *your* install and subscription:

1. **`x-brave-key`** — a static services key baked into your Brave build.
2. **HTTP Message Signature (hs2019)** — an HMAC-SHA256 signature over the
   request-body digest, keyed by a pre-shared key also baked into your
   Brave build. `leo find-key` recovers that key from *your own* Brave
   binary by testing string candidates against a signature you captured
   from your own browser traffic. No key is shipped with this tool.
3. **Premium cookie** — `__Secure-sku#brave-leo-premium=<credential>`.
   Premium credentials are *single-use* time-limited tokens, derived
   locally from a batch Brave downloads into your profile's `Local State`
   (skus state) once you subscribe. `leo import-batch` copies that batch
   into leo's own store; every API call mints a fresh presentation from
   the next unspent credential, exactly like the browser does (HMAC-SHA512
   chain, RFC 9497 finalize). Reusing a credential fails — minting is
   per-request by design.

All of it stays on your machine. The only network calls leo makes are to
Brave's own API, exactly like the browser makes. Credentials are stored
locally with restrictive file permissions; the capture files used during
setup contain your own subscription material — delete them when setup is
done (the guides say so at the right step).

## Requirements

- A Brave browser install with an **active Leo Premium** subscription.
- Python 3.9+ (macOS ships one; on Windows install from python.org and
  tick "Add python.exe to PATH").
- [opencode](https://opencode.ai) (TUI or desktop app) — only if you want
  the agent/coding workflow; `leo ask` / `leo chat` work on their own.
- For the one-time setup capture: [mitmproxy](https://mitmproxy.org)
  (`python3 -m pip install mitmproxy`) — see the setup guides.

## Quick start

Follow the full guide for your OS — it covers the capture step in detail:

- **macOS:** [SETUP-macOS.md](SETUP-macOS.md)
- **Windows:** [SETUP-Windows.md](SETUP-Windows.md)

Short version (after Brave + Leo Premium are working in the browser):

```sh
# 1. Capture ONE Leo request (mitmproxy addon in this folder)
mitmdump -s capture_addon.py
# ...in Brave (launched with --proxy-server=http://127.0.0.1:8080),
#    send Leo one message with Claude Opus selected, then Ctrl-C mitmdump.

# 2. Import everything the capture proves (key, keyId, signing key)
python3 leo.py import-capture

# 3. Copy the credential batch from your Brave profile
python3 leo.py import-batch

# 4. Check health, register opencode, go
python3 leo.py ensure
python3 leo.py opencode-config
python3 leo.py serve          # leave running; open opencode, new chat
```

On macOS you can double-click `leo-bridge.command` instead of step 4's
`serve`; on Windows, double-click `leo-bridge.bat`. `leo-opencode.sh` /
`leo-opencode.bat` run the health check and the bridge together.

If `import-batch` finds no batch: open Brave, send Leo a message, open
account.brave.com, wait for the subscriptions section to render, click
**Refresh Leo AI**, quit Brave completely (so `Local State` flushes),
then run `import-batch` again.

## Commands

```
python3 leo.py ask "explain this error"     one-shot (keeps session history)
echo "text" | python3 leo.py ask "..."      pipe input in
python3 leo.py chat                         interactive REPL
python3 leo.py --model claude-sonnet ask …  pick a model (default: claude-opus)
python3 leo.py --new ask "…"                fresh session
python3 leo.py serve [--port 8765]          OpenAI-compatible local bridge
python3 leo.py opencode-config              register provider in opencode
python3 leo.py import-batch                 copy credential batch from Brave
python3 leo.py batch                        show batch status (counts only)
python3 leo.py mint                         mint one presentation (debug)
python3 leo.py ensure                       credential health check
python3 leo.py find-key --body b.json --signature <sig> [--key-id <id>]
python3 leo.py import-capture [dir]         setup from a mitmproxy capture
python3 leo.py config --brave-key … --key-id …
```

`leo serve` listens on `http://127.0.0.1:8765/v1` by default. opencode
is pointed at it by `opencode-config` (provider `leo`, models
`leo/claude-opus`, `leo/claude-sonnet`, …). Use `--api-key` on `serve`
(and the matching key in the provider settings) if you want the local
endpoint to require a Bearer token.

## Models

All 13 models from Leo's own menu answer on the Premium API. All make
native tool calls except GPT 5.6 Luna (chat only). Context limits are
the values measured live through Leo (see "Context limits" below), and
are what opencode uses to decide when to compact a session.

| Model | Tools | Vision | Context |
|---|---|---|---|
| Claude Opus | yes | yes | 256,000 |
| Claude Sonnet | yes | yes | 256,000 |
| GPT 5.6 Terra | yes | yes | 192,000 |
| Grok 4.6 | yes | yes | 192,000 |
| Qwen 3.5 35B | yes | yes | 192,000 |
| Qwen 3.8 Flash Next | yes | yes | 128,000 |
| DeepSeek V3.2 | yes | — | 128,000 |
| Kimi K2.5 | yes | — | 128,000 |
| Mistral Large 3 | yes | — | 128,000 |
| Nemotron Nano 3 30B | yes | — | 128,000 |
| GLM 4.7 Flash | yes | — | 128,000 |
| GLM 5.3 Flash | yes | — | 128,000 |
| GPT 5.6 Luna | chat only | yes | 128,000 |

## Context limits (measured, not marketing)

Leo's proxy does **not** expose Claude's headline context figures. Measured
live through the API:

- Sonnet recalled a marker placed at the start of a ~299,000-token prompt
  — real context, no silent trimming. Claudes are capped at 256,000 here
  to keep headroom below the failure zone.
- Qwen, Grok and Terra answered cleanly at ~211,000 tokens → 192,000.
- DeepSeek fails around ~160,000 tokens → 128,000.
- At ~400,000+ tokens Leo fails outright (HTTP 413 "Conversation is too
  large" at ~606k; a "There was an issue connecting to the model" failure
  page at ~400–500k). The bridge converts those failure pages into real
  HTTP errors instead of letting an agent build on them as if they were
  model output.

Leo also has **per-model daily rate limits** (HTTP 429). Each model has
its own bucket, so switching models is the legitimate way to keep working
when one bucket is drained; buckets reset at 00:00 UTC.

## Bridge behaviour notes

- **Streams are normalised for strict clients** (opencode v2 requires
  exactly one `finish_reason`, last, before `[DONE]`): post-finish empty
  chunks are dropped, a missing finish is synthesised, `tool_calls` is
  reported when tools fired, and real usage is passed through (including
  the final usage chunk when `stream_options.include_usage` is set).
- **Message shapes opencode sends that Leo rejects are sanitised**:
  thinking/reasoning parts are dropped, file attachments are decoded to
  text, remote image URLs are fetched and inlined as data URLs (Leo
  rejects remote attachments).
- **Upfront refusals are real HTTP errors** (400/429/413 pass through),
  and a stream that dies mid-generation ends *without* a fake finish, so
  the client retries the step instead of accepting truncated output.
- **Large text bursts are paced** into word-sized pieces (max ~2s of
  pacing per response) so rendering looks progressive; tool-call deltas
  are never paced, so execution isn't delayed.
- **Temperature is forwarded** when the client sends it. `max_tokens` and
  `tool_choice` are *not* forwarded — Leo provably ignores both.
- **Concurrency-safe**: credential minting is lock-guarded, so parallel
  opencode sub-agents can't burn each other's single-use credentials.

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `401` from the bridge | Batch exhausted or Brave rotated keys. Re-run `import-batch`; after a Brave upgrade, re-run the capture + `import-capture`. |
| `429` | That model's daily bucket is drained. Wait for 00:00 UTC or switch models. |
| `413` / "Conversation is too large" | Session exceeded Leo's real context wall. Start a new chat (or let opencode compact sooner). |
| opencode shows fewer models than expected | You edited the wrong config, or a project-level `opencode.json` overrides the global one, or the app wasn't fully quit (Cmd+Q / Dock → Quit) after the change. Run `leo.py opencode-config` — it prints the model list it wrote — and check for an `opencode.json` in your project folder. |
| "stream ended without finish_reason" on every step | Stale bridge build, or the bridge process died mid-stream. Update `leo.py`, restart the bridge, new chat. |
| `import-batch` finds nothing | Brave hasn't written the batch yet. Send Leo a message, click **Refresh Leo AI** on account.brave.com, quit Brave fully, retry. |
| `find-key` finds nothing | Wrong binary (on macOS the key lives in the Framework binary inside the `.app`, not the launcher stub — `find-key` scans both automatically when given the app path; on Windows try `chrome.dll` in the versioned Application folder), or the body/signature aren't from the same captured request. |

## Privacy

- Your Brave credentials, signing key and credential batch live only in
  leo's local config directory. They are never sent anywhere except to
  Brave's own API endpoints, in the same shape the browser sends them.
- `leo batch` prints counts only, never credential values.
- Delete `~/leo-capture/` after setup — it holds one captured request.
- This tool is not affiliated with Brave or Anthropic. It is an
  independent client for a subscription you pay for.

## Credits

Built by Cypher Store — https://t.me/Cypherstores_bot

Released as open source. Free to use, share and modify; credit is
appreciated but not required.
