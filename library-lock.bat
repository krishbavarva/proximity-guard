@echo off
rem Library mode: lock the laptop and watch it (unplug / wake / Wi-Fi change / wrong code = alert with location)
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0guard.ps1" -Library
