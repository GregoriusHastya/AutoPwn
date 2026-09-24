#!/usr/bin/env bash
# install.sh — one-shot installer for chall_id
set -e

echo "[*] chall_id installer"

# --- Python version check ---
PY=$(command -v python3 || true)
if [ -z "$PY" ]; then
    echo "[!] python3 not found. Install Python 3.8+ first." >&2
    exit 1
fi
PY_VER=$($PY -c 'import sys; print("%d.%d" % sys.version_info[:2])')
echo "[+] python3 = $PY  ($PY_VER)"

# --- System packages (Linux) ---
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if command -v apt >/dev/null 2>&1; then
        echo "[*] Installing system packages via apt..."
        sudo apt update -qq
        sudo apt install -y python3 python3-pip python3-venv \
                            binutils file gdb gcc
    elif command -v pacman >/dev/null 2>&1; then
        echo "[*] Installing system packages via pacman..."
        sudo pacman -S --noconfirm python python-pip binutils file gdb gcc
    else
        echo "[!] Unsupported Linux distro. Install binutils, file, gdb manually."
    fi
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if command -v brew >/dev/null 2>&1; then
        echo "[*] Installing system packages via brew..."
        brew install python binutils file
    fi
fi

# --- Python venv ---
if [ ! -d "venv" ]; then
    echo "[*] Creating virtualenv..."
    $PY -m venv venv
fi
# shellcheck disable=SC1091
source venv/bin/activate

# --- Pip packages ---
echo "[*] Upgrading pip..."
pip install --upgrade pip wheel setuptools

echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

# --- Optional: angr (large download) ---
read -rp "[?] Install angr for real decompilation? (~400MB) [Y/n] " ans
if [[ "$ans" =~ ^([Yy]|)$ ]]; then
    pip install angr
fi

# --- Sanity check ---
echo "[*] Sanity check..."
python3 -c "import pwn; print('pwntools', pwn.version.__version__)"
python3 -c "import ropgadget" 2>/dev/null && echo "ROPgadget ok" || echo "ROPgadget missing"

echo
echo "[+] Installation complete."
echo "    Activate the venv with: source venv/bin/activate"
echo "    Then run:               python3 chall_id.py ./some_binary"
