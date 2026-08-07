@echo off
setlocal enabledelayedexpansion

rem ============================================================
rem Commit.cmd -- commit + push everything in this folder.
rem Run this from D:\DevTools\Extension\CDNs_WAFs_Detector.
rem
rem Always passes -m to git commit, so it NEVER opens an editor and
rem hangs waiting for input (that's what happened last time: plain
rem `git commit` with no -m opens your default editor, and if that's
rem not obviously a text editor window, it just looks stuck).
rem ============================================================

rem -- Try to read the Chrome build's version out of its manifest.json,
rem    so the commit message says something useful instead of "_".
rem    Falls back to just a timestamp if that file isn't found/parseable.
set VERSION=
for /f "usebackq delims=" %%v in (`powershell -NoProfile -Command "try { (Get-Content 'Chrome_CDNs_WAFs_Detector\manifest.json' -Raw | ConvertFrom-Json).version } catch { '' }"`) do set VERSION=%%v

if "%VERSION%"=="" (
  for /f "usebackq delims=" %%d in (`powershell -NoProfile -Command "Get-Date -Format 'yyyy-MM-dd HH:mm'"`) do set STAMP=%%d
  set MSG=Update !STAMP!
) else (
  set MSG=v!VERSION!
)

echo.
echo === Committing with message: "!MSG!" ===
echo.

git add -A
git commit -m "!MSG!"

if errorlevel 1 (
  echo.
  echo Nothing to commit ^(working tree already matches last commit^), or commit failed.
  echo Skipping push.
  goto :end
)

echo.
echo === Pushing to origin ===
git push

if errorlevel 1 (
  echo.
  echo First push has no upstream set yet -- retrying with --set-upstream...
  for /f "usebackq delims=" %%b in (`git rev-parse --abbrev-ref HEAD`) do set BRANCH=%%b
  git push --set-upstream origin !BRANCH!
)

if errorlevel 1 (
  echo.
  echo ==============================================================
  echo  Push failed. Common causes:
  echo   - Not logged in / no credential helper configured.
  echo   - Remote has commits this doesn't ^(try `git pull` first^).
  echo ==============================================================
) else (
  echo.
  echo Done.
)

:end
pause