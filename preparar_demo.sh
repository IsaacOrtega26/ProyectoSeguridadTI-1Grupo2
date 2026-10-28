#!/usr/bin/env bash
# preparar_demo.sh - Crea los archivos de prueba y los "golden values".
#
#   componentes_buenos/  -> versión original de cada componente (referencia)
#   componentes/         -> copia de trabajo (la que se medirá y se manipulará)
#   golden.json          -> hashes "buenos" que conoce el verificador
set -euo pipefail
cd "$(dirname "$0")"

COMPONENTES=(bios.bin bootloader.bin kernel.bin config.txt)

rm -rf componentes_buenos componentes salida salida_vieja
mkdir -p componentes_buenos

# Contenido aleatorio para simular binarios; config.txt es texto legible
head -c 2048 /dev/urandom > componentes_buenos/bios.bin
head -c 4096 /dev/urandom > componentes_buenos/bootloader.bin
head -c 8192 /dev/urandom > componentes_buenos/kernel.bin
printf 'root=/dev/sda1\nquiet\nsecureboot=on\n' > componentes_buenos/config.txt

cp -r componentes_buenos componentes

python3 verificador.py golden --dir componentes_buenos --out golden.json
echo "Archivos de prueba listos en componentes/ (orden: ${COMPONENTES[*]})"
