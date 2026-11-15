@echo off
setlocal
where cargo >nul 2>nul
if errorlevel 1 (
  echo Rust is not installed. Download rustup-init.exe from https://rustup.rs and run it, then run this file again.
  pause
  exit /b 1
)
cargo build --release
if errorlevel 1 (
  echo Build failed.
  pause
  exit /b 1
)
copy /Y target\release\mini-av.exe mini-av.exe >nul
echo.
echo Done: mini-av.exe is ready in this folder.
pause
