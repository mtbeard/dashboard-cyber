@echo off
chcp 65001 > nul 2> nul
title CyberDashboard - Diagnostic
color 0E

echo.
echo  ========================================
echo   DIAGNOSTIC CYBERDASHBOARD
echo  ========================================
echo.

echo  --- Systeme ---
echo  OS : Windows
ver
echo.

echo  --- Python ---
where python 2>nul
if %ERRORLEVEL% neq 0 (
    echo  [KO] Python introuvable dans le PATH
    echo       -> Installe Python sur python.org et coche "Add to PATH"
) else (
    python --version
    echo  [OK] Python trouve
)
echo.

echo  --- pip ---
pip --version 2>nul
if %ERRORLEVEL% neq 0 (
    echo  [KO] pip introuvable
) else (
    echo  [OK] pip disponible
)
echo.

echo  --- Modules Python requis ---
python -c "import fastapi; print('[OK] fastapi', fastapi.__version__)" 2>nul || echo  [KO] fastapi manquant - lance start.bat pour l'installer
python -c "import uvicorn; print('[OK] uvicorn', uvicorn.__version__)" 2>nul || echo  [KO] uvicorn manquant
python -c "import httpx; print('[OK] httpx', httpx.__version__)" 2>nul || echo  [KO] httpx manquant
python -c "import pydantic; print('[OK] pydantic', pydantic.__version__)" 2>nul || echo  [KO] pydantic manquant
echo.

echo  --- Fichiers du projet ---
if exist "%~dp0backend\main.py"    (echo  [OK] backend\main.py) else (echo  [KO] backend\main.py MANQUANT)
if exist "%~dp0backend\seed.py"    (echo  [OK] backend\seed.py) else (echo  [KO] backend\seed.py MANQUANT)
if exist "%~dp0backend\database.py"(echo  [OK] backend\database.py) else (echo  [KO] backend\database.py MANQUANT)
if exist "%~dp0frontend\index.html"(echo  [OK] frontend\index.html) else (echo  [KO] frontend\index.html MANQUANT)
if exist "%~dp0.env"               (echo  [OK] .env present) else (echo  [INFO] .env absent - cles API non configurees)
if exist "%~dp0database.db"        (echo  [OK] database.db presente) else (echo  [INFO] database.db absente - sera creee au 1er lancement)
echo.

echo  --- Port 8000 ---
netstat -an 2>nul | findstr ":8000" > nul
if %ERRORLEVEL% equ 0 (
    echo  [INFO] Port 8000 deja occupe - backend peut-etre deja lance
) else (
    echo  [OK] Port 8000 libre
)
echo.

echo  ========================================
echo   Diagnostic termine
echo   Appuie sur une touche pour fermer
echo  ========================================
pause > nul
