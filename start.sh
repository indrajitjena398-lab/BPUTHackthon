#!/bin/bash
# CYBERGUARD Enterprise Threat Defense Platform
# AI-Powered Cyber Threat, Phishing, Deepfake & Impersonation Defense

echo "====================================================================="
echo " CYBERGUARD Enterprise Threat Defense Platform"
echo " AI-Powered Cyber Threat, Phishing, Deepfake & Impersonation Defense"
echo "====================================================================="
echo ""

# Ensure trap exits child processes on SIGINT
cleanup() {
    echo ""
    echo "Shutting down CYBERGUARD services..."
    kill $(jobs -p) 2>/dev/null
    exit
}
trap cleanup SIGINT SIGTERM

echo "Starting CyberGuard Backend (FastAPI on http://127.0.0.1:8000)..."
cd backend
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload &
BACKEND_PID=$!
cd ..

sleep 3

echo "Starting CyberGuard Frontend (Next.js on http://localhost:3000)..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

echo ""
echo "====================================================================="
echo " CyberGuard is now running!"
echo " - Frontend UI: http://localhost:3000"
echo " - Backend API: http://127.0.0.1:8000"
echo " - API Docs:    http://127.0.0.1:8000/docs"
echo " Press Ctrl+C to terminate all services."
echo "====================================================================="

wait
