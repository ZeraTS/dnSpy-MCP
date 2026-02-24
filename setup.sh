#!/bin/bash

set -e

echo "dnspy-mcp Setup Script"
echo "======================"
echo

# Check Python version
echo "[1] Checking Python 3.10+"
if ! python3 --version | grep -qE "3\.(1[0-9]|[2-9][0-9])"; then
    echo "ERROR: Python 3.10+ required"
    exit 1
fi
echo "OK: $(python3 --version)"
echo

# Check .NET SDK (for CLI debugger)
echo "[2] Checking .NET SDK (optional, for CLI debugger)"
if command -v dotnet &> /dev/null; then
    echo "OK: $(dotnet --version)"
else
    echo "WARNING: .NET SDK not found. CLI debugger will not work."
    echo "Install from: https://dotnet.microsoft.com/download"
fi
echo

# Create virtual environment
echo "[3] Creating virtual environment"
python3 -m venv venv
source venv/bin/activate
echo "OK"
echo

# Install dependencies
echo "[4] Installing Python dependencies"
pip install -q -r requirements.txt
echo "OK"
echo

# Setup .env file
echo "[5] Setting up environment"
if [ ! -f .env ]; then
    cp .env.example .env
    echo "Created .env from template (edit with your configuration)"
else
    echo ".env already exists (skipping)"
fi
echo

# Build CLI debugger (optional)
if command -v dotnet &> /dev/null; then
    echo "[6] Building CLI debugger"
    dotnet build -c Release -q 2>/dev/null || echo "WARNING: Build failed (optional)"
    echo "OK"
else
    echo "[6] Skipping CLI debugger build (dotnet not found)"
fi
echo

echo "Setup complete!"
echo
echo "To start the daemon:"
echo "  source venv/bin/activate"
echo "  export \$(cat .env | xargs)"
echo "  python3 daemon.py"
echo
echo "Or use Docker:"
echo "  docker-compose up"
echo
