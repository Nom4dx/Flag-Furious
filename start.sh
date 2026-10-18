#!/usr/bin/env bash
# Avvia Forensic Hub dalla directory corretta usando l'ambiente virtuale locale.
# Le opzioni ricevute vengono inoltrate a `python -m app` (es. --no-browser).

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$PROJECT_DIR"

# La configurazione locale è facoltativa. Le variabili documentate in
# .env.example vengono esportate prima di importare l'applicazione.
if [[ -f "$PROJECT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$PROJECT_DIR/.env"
  set +a
fi

if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
  PYTHON="$PROJECT_DIR/.venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON="$(command -v python3)"
else
  echo "Errore: Python 3.11 o successivo non è disponibile." >&2
  exit 1
fi

"$PYTHON" - <<'PY'
import sys

if sys.version_info < (3, 11):
    raise SystemExit("Errore: Forensic Hub richiede Python 3.11 o successivo.")

missing = []
for module in ("fastapi", "pydantic", "uvicorn", "jsonschema", "regex"):
    try:
        __import__(module)
    except ImportError:
        missing.append(module)

if missing:
    raise SystemExit(
        "Dipendenze mancanti: " + ", ".join(missing)
        + "\nEsegui: .venv/bin/pip install -r requirements.txt"
    )
PY

PORT="${HUB_PORT:-8000}"
NO_BROWSER=false
EXPECT_PORT=false
for argument in "$@"; do
  if [[ "$EXPECT_PORT" == true ]]; then
    PORT="$argument"
    EXPECT_PORT=false
    continue
  fi
  case "$argument" in
    --port) EXPECT_PORT=true ;;
    --port=*) PORT="${argument#--port=}" ;;
    --no-browser) NO_BROWSER=true ;;
  esac
done

if [[ "$EXPECT_PORT" == true || ! "$PORT" =~ ^[0-9]+$ || "$PORT" -lt 1 || "$PORT" -gt 65535 ]]; then
  echo "Errore: porta non valida: $PORT" >&2
  exit 2
fi

URL="http://127.0.0.1:$PORT"
if "$PYTHON" - "$PORT" <<'PY'
import json
import sys
import urllib.request

try:
    with urllib.request.urlopen(
        f"http://127.0.0.1:{sys.argv[1]}/api/health", timeout=0.7
    ) as response:
        value = json.load(response)
    raise SystemExit(0 if value.get("status") == "ok" else 1)
except Exception:
    raise SystemExit(1)
PY
then
  echo "Forensic Hub è già attivo su $URL"
  if [[ "$NO_BROWSER" == false ]] && command -v xdg-open >/dev/null 2>&1; then
    xdg-open "$URL" >/dev/null 2>&1 &
  fi
  exit 0
fi

if ! command -v bwrap >/dev/null 2>&1; then
  echo "Attenzione: bubblewrap non è installato; i plugin isolati non saranno disponibili." >&2
fi

echo "Avvio Forensic Hub su $URL"
echo "Premi Ctrl+C per arrestare il servizio."
exec "$PYTHON" -m app "$@"
