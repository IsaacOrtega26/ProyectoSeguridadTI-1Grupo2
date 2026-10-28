#!/usr/bin/env bash
# medir_arranque.sh - "Máquina medida"
#
# 1) Pone el PCR 16 en ceros (estado inicial).
# 2) Por cada componente, en orden: calcula su SHA-256, lo extiende en el PCR 16
#    y lo anota en el registro de eventos.
# 3) Pide al TPM un quote firmado con la AK, incluyendo el NONCE que mandó el verificador.
#
# Uso:  ./medir_arranque.sh NONCE_HEX [DIR_COMPONENTES] [DIR_SALIDA]
# Ej.:  ./medir_arranque.sh "$(python3 verificador.py nonce)"
set -euo pipefail
cd "$(dirname "$0")"

# Siempre el TPM simulado (nunca el TPM físico del equipo), aunque TPM2TOOLS_TCTI esté definida.
export TPM2TOOLS_TCTI="${TCTI_DEMO:-swtpm:port=2321}"

NONCE="${1:-}"
DIR_COMP="${2:-componentes}"
DIR_OUT="${3:-salida}"
PCR=16
AK_HANDLE=0x81010002
COMPONENTES=(bios.bin bootloader.bin kernel.bin config.txt)   # ORDEN DE LA CADENA

if [[ -z "$NONCE" ]]; then
  echo "Uso: $0 NONCE_HEX [DIR_COMPONENTES] [DIR_SALIDA]" >&2
  echo "El nonce lo genera el VERIFICADOR:  python3 verificador.py nonce" >&2
  exit 1
fi
if ! [[ "$NONCE" =~ ^([0-9a-fA-F]{2})+$ ]]; then
  echo "El nonce debe ser hexadecimal con cantidad par de dígitos." >&2
  exit 1
fi
tpm2_getcap properties-fixed >/dev/null 2>&1 || { echo "No hay TPM disponible. Corre primero ./setup_tpm.sh" >&2; exit 1; }
tpm2_getcap handles-persistent 2>/dev/null | grep -qi "$AK_HANDLE" || { echo "No existe la AK. Corre primero ./setup_tpm.sh" >&2; exit 1; }

mkdir -p "$DIR_OUT"
EVENTLOG="$DIR_OUT/eventlog.txt"
: > "$EVENTLOG"

echo "== MÁQUINA MEDIDA =="
echo "Nonce recibido: $NONCE"

# 1) Estado inicial del PCR 16 (el PCR de depuración sí se puede reiniciar)
tpm2_pcrreset "$PCR"

# 2) Medir y extender, en orden
n=0
for f in "${COMPONENTES[@]}"; do
  n=$((n + 1))
  ruta="$DIR_COMP/$f"
  [[ -f "$ruta" ]] || { echo "Falta el componente: $ruta" >&2; exit 1; }
  h=$(sha256sum "$ruta" | cut -d' ' -f1)
  tpm2_pcrextend "${PCR}:sha256=${h}"
  echo "$f $h" >> "$EVENTLOG"
  printf '  [%d/%d] %-15s %s\n' "$n" "${#COMPONENTES[@]}" "$f" "$h"
done

valor=$(tpm2_pcrread "sha256:${PCR}" | awk '/16:/ {print $2}')
echo "PCR ${PCR} final: ${valor}"

# 3) Quote firmado con la AK, ligado al nonce
tpm2_quote -c "$AK_HANDLE" -l "sha256:${PCR}" -q "$NONCE" \
  -m "$DIR_OUT/quote.msg" -s "$DIR_OUT/quote.sig" -o "$DIR_OUT/quote.pcrs" -g sha256 >/dev/null
tpm2_flushcontext -t >/dev/null 2>&1 || true

echo "Quote generado en $DIR_OUT/ (quote.msg, quote.sig, quote.pcrs, eventlog.txt)"
