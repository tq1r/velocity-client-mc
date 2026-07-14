#!/bin/bash
echo "============================================"
echo "  Velocity Client - Auth Server"
echo "============================================"
echo ""

# Check Python
if command -v python3 &> /dev/null; then
    PY=python3
elif command -v python &> /dev/null; then
    PY=python
else
    echo "[ERROR] Python not found! Install Python 3.7+"
    exit 1
fi

# Check Flask
$PY -c "import flask" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[SETUP] Installing Flask..."
    $PY -m pip install flask
    echo ""
fi

# Get local IP for convenience
LOCAL_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
if [ -z "$LOCAL_IP" ]; then
    LOCAL_IP=$(ifconfig 2>/dev/null | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)
fi

echo "[INFO] Starting server on all interfaces (0.0.0.0:5000)"
echo "[INFO] Admin Panel: http://localhost:5000/admin"
if [ -n "$LOCAL_IP" ]; then
    echo "[INFO] From other devices: http://$LOCAL_IP:5000/admin"
fi
echo "[INFO] Press Ctrl+C to stop"
echo ""

$PY server.py --host 0.0.0.0 --port 5000