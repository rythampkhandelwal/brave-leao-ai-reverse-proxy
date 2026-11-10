@echo off
REM leo-bridge - open-source edition | Built by Cypher Store - https://t.me/Cypherstores_bot
REM Double-click to start the Leo bridge only (for the opencode desktop app).
cd /d %~dp0
py -3 leo.py serve 2>nul || python leo.py serve
pause
