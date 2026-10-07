@echo off
echo =====================================================================
echo  CYBERGUARD Enterprise Threat Defense Platform
echo  AI-Powered Cyber Threat, Phishing, Deepfake & Impersonation Defense
echo =====================================================================
echo.
echo Starting CyberGuard Backend (FastAPI on http://127.0.0.1:8000)...
start "CyberGuard Backend" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 3 /nobreak >nul

echo Starting CyberGuard Frontend (Next.js on http://localhost:3000)...
start "CyberGuard Frontend" cmd /k "cd frontend && npm.cmd run dev"

echo.
echo =====================================================================
echo  CyberGuard is now launching!
echo  - Frontend UI: http://localhost:3000
echo  - Backend API: http://127.0.0.1:8000
echo  - API Docs:    http://127.0.0.1:8000/docs
echo =====================================================================
pause
