@echo off
chcp 65001 > nul 2> nul
title CyberDashboard
color 0A

:: Toujours garder la fenetre ouverte, meme en cas d'erreur
:: La fenetre ne se fermera QUE quand l'utilisateur appuie sur une touche

echo.
echo  ============================================
echo   CYBER DASHBOARD - Threat Intelligence
echo  ============================================
echo.
echo  [*] Dossier courant : %~dp0
echo.

:: ===================================================
:: ETAPE 1 - Verifier Python
:: ===================================================
echo  [1/5] Verification de Python...

python --version > nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERREUR] Python est introuvable dans le PATH Windows.
    echo.
    echo  Solutions :
    echo    1. Installe Python depuis https://www.python.org/downloads/
    echo    2. IMPORTANT : Coche "Add Python to PATH" pendant l'installation
    echo    3. Apres installation, ferme et relance start.bat
    echo.
    goto :ERREUR_FINALE
)

for /f "tokens=*" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] %PYVER% detecte

:: ===================================================
:: ETAPE 2 - Se placer dans le bon dossier
:: ===================================================
echo.
echo  [2/5] Navigation vers le backend...

cd /d "%~dp0backend"
if %ERRORLEVEL% neq 0 (
    echo  [ERREUR] Impossible d'acceder au dossier backend
    echo  Chemin attendu : %~dp0backend
    goto :ERREUR_FINALE
)
echo  [OK] Dossier backend : %CD%

:: ===================================================
:: ETAPE 3 - Installer les dependances
:: ===================================================
echo.
echo  [3/5] Installation des dependances Python...
echo  (peut prendre 1-2 minutes au premier lancement)
echo.

python -m pip install --upgrade pip --quiet
python -m pip install fastapi "uvicorn[standard]" httpx pydantic python-dotenv deep-translator
if %ERRORLEVEL% neq 0 (
    echo.
    echo  [ERREUR] L'installation des modules a echoue.
    echo  Essaie de lancer cette commande manuellement dans un terminal :
    echo    python -m pip install fastapi uvicorn httpx pydantic python-dotenv
    echo.
    goto :ERREUR_FINALE
)
echo.
echo  [OK] Dependances installees

:: ===================================================
:: ETAPE 4 - Seeding initial si premiere fois
:: ===================================================
echo.
echo  [4/5] Verification de la base de donnees...

if not exist "%~dp0database.db" (
    echo  [*] Premier lancement - creation de la base...
    echo      Insertion des donnees de demonstration...
    echo.
    python seed.py
    if %ERRORLEVEL% neq 0 (
        echo.
        echo  [ATTENTION] Le seeding a rencontre une erreur.
        echo  La base sera creee avec uniquement les donnees demo.
    )
    echo.
    echo  [OK] Base de donnees creee
) else (
    echo  [OK] Base de donnees existante detectee
)

:: ===================================================
:: ETAPE 5 - Lancer le backend FastAPI
:: ===================================================
echo.
echo  [5/5] Lancement du backend FastAPI...
echo.

:: Lancer uvicorn dans une nouvelle fenetre qui reste ouverte
start "CyberDashboard - Backend API" cmd /k "cd /d "%~dp0backend" && echo [API] Demarrage de FastAPI sur http://127.0.0.1:8000 ... && python -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload && echo. && echo [API] Serveur arrete. && pause"

:: Attendre que le backend soit pret
echo  [*] Attente du backend (max 20 secondes)...
set /a RETRIES=0

:WAIT_LOOP
timeout /t 2 /nobreak > nul

:: Tester si le backend repond
curl -s --max-time 2 http://127.0.0.1:8000/health > nul 2>&1
if %ERRORLEVEL% equ 0 (
    goto :BACKEND_READY
)

python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)" > nul 2>&1
if %ERRORLEVEL% equ 0 (
    goto :BACKEND_READY
)

set /a RETRIES+=1
echo  [*] Tentative %RETRIES%/10 - backend pas encore pret...

if %RETRIES% lss 10 goto :WAIT_LOOP

echo.
echo  [ATTENTION] Le backend met du temps a demarrer.
echo  Verifie la fenetre "CyberDashboard - Backend API" pour voir les erreurs.
echo.

:BACKEND_READY
echo.
echo  [OK] Backend operationnel !
echo.

:: ===================================================
:: Ouvrir le frontend
:: ===================================================
echo  [*] Ouverture du dashboard dans le navigateur...
start "" "%~dp0frontend\index.html"

echo.
echo  ============================================
echo   Dashboard lance avec succes !
echo  ============================================
echo.
echo   Interface  : %~dp0frontend\index.html
echo   API        : http://127.0.0.1:8000
echo   API Docs   : http://127.0.0.1:8000/docs
echo.
echo   Pour ajouter tes cles API : edite le fichier .env
echo   Pour re-seeder la base   : python backend\seed.py
echo.
echo   Une fenetre "Backend API" est ouverte en arriere-plan.
echo   Ferme-la pour arreter le serveur.
echo.
echo  Appuie sur une touche pour fermer CETTE fenetre...
pause > nul
exit /b 0

:: ===================================================
:: Gestion des erreurs
:: ===================================================
:ERREUR_FINALE
echo.
echo  ============================================
echo   ERREUR - Le dashboard ne peut pas demarrer
echo  ============================================
echo.
echo  Appuie sur une touche pour fermer...
pause > nul
exit /b 1
