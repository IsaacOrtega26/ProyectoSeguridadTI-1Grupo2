#!/usr/bin/env bash
# setup_tpm.sh - Prepara el TPM simulado (swtpm) y crea las llaves EK y AK.
# Se corre UNA vez (o cada vez que se reinicie la VM). Es seguro repetirlo.
#
# Uso:   ./setup_tpm.sh          -> levanta swtpm y crea EK/AK si no existen
#        ./setup_tpm.sh parar    -> apaga swtpm
set -euo pipefail
cd "$(dirname "$0")"

PUERTO=2321
CONTROL=2322
EK_HANDLE=0x81010001      # EK persistente
AK_HANDLE=0x81010002      # AK persistente (la que firma los quotes)
export TPM2TOOLS_TCTI="swtpm:port=${PUERTO}"

if [[ "${1:-}" == "parar" ]]; then
  if [[ -f swtpm.pid ]] && kill "$(cat swtpm.pid)" 2>/dev/null; then
    rm -f swtpm.pid
    echo "swtpm detenido."
  else
    echo "swtpm no estaba corriendo."
  fi
  exit 0
fi

for cmd in swtpm tpm2_createek tpm2_quote openssl python3; do
  command -v "$cmd" >/dev/null || { echo "Falta '$cmd'. Instala: sudo apt install swtpm swtpm-tools tpm2-tools"; exit 1; }
done

mkdir -p tpm_state claves

# 1) Levantar swtpm si no responde
if ! tpm2_getcap properties-fixed >/dev/null 2>&1; then
  swtpm socket --tpm2 --tpmstate dir=tpm_state \
    --server type=tcp,port=${PUERTO} --ctrl type=tcp,port=${CONTROL} \
    --flags not-need-init,startup-clear --daemon --pid file=swtpm.pid
  sleep 1
  tpm2_getcap properties-fixed >/dev/null 2>&1 || { echo "No se pudo iniciar swtpm."; exit 1; }
  echo "swtpm iniciado (puerto ${PUERTO})."
else
  echo "swtpm ya estaba corriendo."
fi

handles=$(tpm2_getcap handles-persistent 2>/dev/null || true)

# 2) Endorsement Key (identidad de fábrica del TPM)
if grep -qi "${EK_HANDLE}" <<<"$handles"; then
  echo "EK ya existe (${EK_HANDLE})."
else
  tpm2_createek -c claves/ek.ctx -G rsa -u claves/ek.pub >/dev/null
  tpm2_evictcontrol -C o -c claves/ek.ctx "${EK_HANDLE}" >/dev/null
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  echo "EK creada y guardada en ${EK_HANDLE}."
fi

# 3) Attestation Key (firma los quotes), ligada a la EK
if grep -qi "${AK_HANDLE}" <<<"$handles"; then
  echo "AK ya existe (${AK_HANDLE})."
else
  tpm2_createak -C "${EK_HANDLE}" -c claves/ak.ctx -G rsa -s rsassa -g sha256 \
    -u claves/ak.pub -f pem -n claves/ak.name >/dev/null
  tpm2_evictcontrol -C o -c claves/ak.ctx "${AK_HANDLE}" >/dev/null
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  echo "AK creada y guardada en ${AK_HANDLE}."
fi

# 4) La llave pública de la AK es lo que conoce el verificador
[[ -f claves/ak.pub ]] || tpm2_readpublic -c "${AK_HANDLE}" -f pem -o claves/ak.pub >/dev/null
echo "Listo. Llave pública de la AK: claves/ak.pub"
