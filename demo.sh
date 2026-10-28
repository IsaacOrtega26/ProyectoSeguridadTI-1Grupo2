#!/usr/bin/env bash
# demo.sh - Corre las demos de clase, una tras otra.
#
#   Demo 1: arranque limpio                       -> CONFIABLE
#   Demo 2: un byte de kernel.bin modificado      -> NO CONFIABLE (señala kernel.bin)
#   Demo 3: quote viejo con un nonce nuevo        -> NO CONFIABLE (nonce no coincide)
#   Demo 4 (extra): log de eventos falsificado    -> NO CONFIABLE (log inconsistente)
#
# Uso:  ./demo.sh                 (pausa entre pasos; pulsa Enter para avanzar)
#       SIN_PAUSA=1 ./demo.sh     (corre todo de corrido)
set -uo pipefail
cd "$(dirname "$0")"

NEG=$'\033[1m'; AZUL=$'\033[94m'; FIN=$'\033[0m'
[[ -t 1 ]] || { NEG=""; AZUL=""; FIN=""; }

pausa() { [[ -n "${SIN_PAUSA:-}" ]] || read -r -p "   ⏎  Enter para continuar..." _ ; echo; }
titulo() { echo; echo "${NEG}${AZUL}════════════════════════════════════════════════════════════${FIN}"; echo "${NEG}${AZUL}  $1${FIN}"; echo "${NEG}${AZUL}════════════════════════════════════════════════════════════${FIN}"; }

# Cambia un solo byte (XOR 0x01) del archivo, en la posición dada
voltear_byte() {
  local archivo="$1" pos="${2:-10}" orig nuevo
  orig=$(dd if="$archivo" bs=1 skip="$pos" count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
  nuevo=$(( orig ^ 1 ))
  printf "\\x$(printf '%02x' "$nuevo")" | dd of="$archivo" bs=1 seek="$pos" count=1 conv=notrunc 2>/dev/null
}

# Verificador genera el nonce -> máquina mide y firma -> verificador verifica
ronda() {  # ronda DIR_SALIDA
  local salida="$1" nonce
  nonce=$(python3 verificador.py nonce)
  ./medir_arranque.sh "$nonce" componentes "$salida"
  echo
  python3 verificador.py verificar --nonce "$nonce" --dir "$salida"
}

# --- Preparación ---
titulo "Preparación: TPM simulado, llaves EK/AK y archivos de prueba"
./setup_tpm.sh || exit 1
./preparar_demo.sh || exit 1
pausa

# --- Demo 1 ---
titulo "DEMO 1 · Arranque limpio"
ronda salida
rm -rf salida_vieja && cp -r salida salida_vieja      # guardamos este quote para la demo 3
pausa

# --- Demo 2 ---
titulo "DEMO 2 · Rootkit simulado: se modifica 1 byte de kernel.bin"
echo "Hash de kernel.bin ANTES : $(sha256sum componentes/kernel.bin | cut -c1-32)..."
voltear_byte componentes/kernel.bin 10
echo "Hash de kernel.bin DESPUÉS: $(sha256sum componentes/kernel.bin | cut -c1-32)..."
echo
ronda salida
pausa

# --- Demo 3 ---
titulo "DEMO 3 · Ataque de repetición: quote viejo (de la demo 1) con un nonce nuevo"
echo "El atacante reenvía el quote de cuando todo estaba limpio (salida_vieja/)."
nonce_nuevo=$(python3 verificador.py nonce)
python3 verificador.py verificar --nonce "$nonce_nuevo" --dir salida_vieja
pausa

# --- Demo 4 (extra) ---
titulo "DEMO 4 (extra) · El atacante edita el registro de eventos para ocultar el kernel"
echo "kernel.bin sigue modificado; ahora el log dice que el hash es el bueno."
nonce=$(python3 verificador.py nonce)
./medir_arranque.sh "$nonce" componentes salida_falsa >/dev/null
bueno=$(sha256sum componentes_buenos/kernel.bin | cut -d' ' -f1)
sed -i "s/^kernel.bin .*/kernel.bin $bueno/" salida_falsa/eventlog.txt
python3 verificador.py verificar --nonce "$nonce" --dir salida_falsa
pausa

# --- Restaurar ---
cp componentes_buenos/kernel.bin componentes/kernel.bin
rm -rf salida_falsa
titulo "Fin. kernel.bin restaurado. Para repetir: ./demo.sh"
