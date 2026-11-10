@echo off
REM leo-opencode - open-source edition | Built by Cypher Store - https://t.me/Cypherstores_bot
REM Health-check the credential batch, then start the local Leo bridge.
REM Run this, leave the window open, then open the opencode desktop app.
cd /d %~dp0
py -3 leo.py ensure 2>nul || python leo.py ensure 2>nul
py -3 leo.py serve 2>nul || python leo.py serve
pause
