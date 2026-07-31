@echo off
setlocal enabledelayedexpansion

rem ============================================================
rem Commit.cmd — combine Chrome_CDNs_WAFs_Detector and
rem FireFox_CDNs_WAFs_Detector into ONE repo, replacing whatever
rem is currently at the remote entirely (force-push).
rem
rem Run this from D:\DevTools\Extension (the parent folder that
rem directly contains both extension folders).
rem ============================================================

set REPO_URL=https://github.com/VuJohn123/CDNs_WAFs_Detector.git
set BRANCH=main

echo.
echo ==============================================================
echo  This will REPLACE the entire contents of:
echo    %REPO_URL%
echo  with what's in this folder right now (force-push).
echo  Anything currently in that repo and not here will be GONE.
echo ==============================================================
echo.
choice /M "Continue"
if errorlevel 2 goto :end
if errorlevel 1 goto :run

:run

rem ── Step 1: strip any nested .git folders from the two subprojects.
rem    Each was previously its own standalone repo. If left in place,
rem    `git add` at this parent level would only record them as empty
rem    submodule links, NOT their actual files.
if exist "Chrome_CDNs_WAFs_Detector\.git" (
  echo Removing nested .git in Chrome_CDNs_WAFs_Detector...
  rmdir /s /q "Chrome_CDNs_WAFs_Detector\.git"
)
if exist "FireFox_CDNs_WAFs_Detector\.git" (
  echo Removing nested .git in FireFox_CDNs_WAFs_Detector...
  rmdir /s /q "FireFox_CDNs_WAFs_Detector\.git"
)

rem ── Step 2: also drop the per-subproject Commit.cmd scripts and any
rem    leftover backup zips so they don't ride along into the new repo.
if exist "Chrome_CDNs_WAFs_Detector\Commit.cmd" del /q "Chrome_CDNs_WAFs_Detector\Commit.cmd"
if exist "FireFox_CDNs_WAFs_Detector\Commit.cmd" del /q "FireFox_CDNs_WAFs_Detector\Commit.cmd"
if exist "FireFox_CDNs_WAFs_Detector\L.zip" del /q "FireFox_CDNs_WAFs_Detector\L.zip"

rem ── Step 3: init a repo at this parent level if one doesn't exist yet.
if not exist ".git" (
  echo Initializing new git repo...
  git init
  git branch -M %BRANCH%
) else (
  echo Existing .git found at this level — reusing it.
  git checkout -B %BRANCH%
)

rem ── Step 4: write a top-level .gitignore covering both subprojects
rem    (patterns with no leading slash match at any depth in git).
(
  echo # Archives / temp / OS junk
  echo *.zip
  echo *.tmp
  echo *.log
  echo *.swp
  echo .DS_Store
  echo Thumbs.db
  echo node_modules/
  echo .vscode/
  echo.
  echo # Cloudflare Workers local dev cache — never commit this
  echo .wrangler/
) > .gitignore

rem ── Step 5: point at the target repo.
git remote remove origin >nul 2>&1
git remote add origin %REPO_URL%

rem ── Step 6: stage everything, commit, force-push.
git add -A
git commit -m "Combine Chrome + Firefox builds into one repo (v9.5.8)"
if errorlevel 1 (
  echo.
  echo Nothing to commit — working tree already matches last commit here.
)

echo.
echo Pushing to %REPO_URL% (branch %BRANCH%, force)...
git push -f origin %BRANCH%

if errorlevel 1 (
  echo.
  echo ==============================================================
  echo  Push failed. Common causes:
  echo   - Not logged in: run `git config --global user.name "..."`
  echo     and `git config --global user.email "..."` first, and make
  echo     sure a GitHub credential/login prompt isn't waiting hidden
  echo     behind this window.
  echo   - The repo https://github.com/VuJohn123/CDNs_WAFs_Detector
  echo     doesn't exist yet — create it empty on GitHub first
  echo     ^(no README/license, so there's nothing to conflict with^).
  echo ==============================================================
) else (
  echo.
  echo Done. https://github.com/VuJohn123/CDNs_WAFs_Detector is now
  echo exactly what's in this folder.
)

:end
pause