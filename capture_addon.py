# leo capture addon - open-source edition | Built by Cypher Store - https://t.me/Cypherstores_bot
"""mitmproxy addon: capture ONE Brave Leo Premium request for leo-cli setup.

Run:  mitmdump -s capture_addon.py        (writes to ~/leo-capture/)
Then in Brave (launched with --proxy-server=http://127.0.0.1:8080) send Leo
one message with Claude Opus selected. This saves, for the first matching
request only:

    ~/leo-capture/body.json     exact request body (ground truth)
    ~/leo-capture/headers.json  its headers (x-brave-key, Authorization, ...)

Then stop mitmdump (Ctrl-C) and run:  python3 leo.py import-capture
Nothing leaves your machine; the files contain your own subscription
credential material, so delete ~/leo-capture once setup is done.
"""
import json
import os
from pathlib import Path

OUT = Path(os.environ.get("LEO_CAPTURE_DIR", Path.home() / "leo-capture"))
_done = False


def request(flow):
    global _done
    if _done:
        return
    host = flow.request.pretty_host or ""
    if "ai-chat" not in host or "/v1/chat/completions" not in flow.request.path:
        return
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "body.json").write_bytes(flow.request.raw_content or b"")
    headers = {k: v for k, v in flow.request.headers.items()}
    (OUT / "headers.json").write_text(json.dumps(headers, indent=2))
    _done = True
    print(f"\n[leo-capture] saved Leo request to {OUT} - "
          "you can Ctrl-C mitmdump now, quit Brave, and run: "
          "python3 leo.py import-capture\n")
