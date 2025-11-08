#!/usr/bin/env bash
set -euo pipefail

APP_NAME="Ai-NmapX"
REPO_URL="https://github.com/HackerBlazeX/Ai-NmapX"
INSTALL_DIR="${HOME}/.ai-nmapx"
VENV_DIR="${INSTALL_DIR}/venv"
LAUNCHER="/usr/local/bin/ai-nmapx"

echo "==> Installing ${APP_NAME} …"

# 1) OS deps
if ! command -v nmap >/dev/null 2>&1; then
  echo "==> Installing nmap (requires sudo)…"
  if command -v apt >/dev/null 2>&1; then
    sudo apt update -y && sudo apt install -y nmap python3-venv python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Sy --noconfirm nmap python python-pip
  else
    echo "Please install nmap and Python3 manually, then re-run."; exit 1
  fi
fi

# 2) Fetch/refresh repo
mkdir -p "${INSTALL_DIR}"
if [ -d "${INSTALL_DIR}/repo/.git" ]; then
  echo "==> Updating existing clone…"
  git -C "${INSTALL_DIR}/repo" pull --ff-only
else
  echo "==> Cloning repo…"
  git clone --depth 1 "${REPO_URL}" "${INSTALL_DIR}/repo"
fi

# 3) Python venv
if [ ! -d "${VENV_DIR}" ]; then
  echo "==> Creating Python venv…"
  python3 -m venv "${VENV_DIR}"
fi

echo "==> Installing Python packages…"
"${VENV_DIR}/bin/pip" install --upgrade pip
# if requirements.txt missing, fallback to minimal deps
if [ -f "${INSTALL_DIR}/repo/requirements.txt" ]; then
  "${VENV_DIR}/bin/pip" install -r "${INSTALL_DIR}/repo/requirements.txt"
else
  "${VENV_DIR}/bin/pip" install colorama rich || true
fi

# 4) Create launcher
echo "==> Creating launcher at ${LAUNCHER} (sudo)…"
TMP_LAUNCHER="$(mktemp)"
cat > "${TMP_LAUNCHER}" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
APP_DIR="${HOME}/.ai-nmapx"
VENV_DIR="${APP_DIR}/venv"
SCRIPT="${APP_DIR}/repo/ai_nmapx.py"

if [ ! -f "${SCRIPT}" ]; then
  echo "Ai-NmapX is not installed correctly. Re-run the installer."; exit 1
fi

# Prefer HTML reports by default (already true inside the script).
exec "${VENV_DIR}/bin/python3" "${SCRIPT}" "$@"
EOF
chmod +x "${TMP_LAUNCHER}"
sudo mv "${TMP_LAUNCHER}" "${LAUNCHER}"

echo "==> Done! Try:  ai-nmapx -i"
echo "Tip: Interactive mode lets you choose options without remembering commands."
