#!/usr/bin/env python3
"""
verificador.py - "Verificador" de la atestación remota (Proyecto 2, Grupo 2)

Subcomandos:
  nonce                      Genera un nonce aleatorio (lo manda el verificador a la máquina).
  golden --dir DIR           Calcula los hashes "buenos" de cada componente (golden values).
  verificar --nonce HEX      Verifica el quote y responde CONFIABLE / NO CONFIABLE.

Qué comprueba "verificar":
  1. Con tpm2_checkquote: firma de la AK, nonce y que los PCR coincidan con el quote.
  2. Calcula el valor esperado del PCR 16 a partir de los golden values.
  3. Si no coincide, usa el registro de eventos para señalar el componente culpable
     (solo si el log reproduce el PCR firmado; si no, el log fue manipulado).
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys

ORDEN_DEFAULT = ["bios.bin", "bootloader.bin", "kernel.bin", "config.txt"]
PCR_INDEX = 16

VERDE, ROJO, AMARILLO, NEGRITA, FIN = "\033[92m", "\033[91m", "\033[93m", "\033[1m", "\033[0m"
if not sys.stdout.isatty():
    VERDE = ROJO = AMARILLO = NEGRITA = FIN = ""


# ---------- utilidades ----------
def sha256_archivo(ruta):
    with open(ruta, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def extender(pcr: bytes, hash_hex: str) -> bytes:
    """Misma operación que el TPM: PCR_nuevo = SHA-256(PCR_anterior || medición)."""
    return hashlib.sha256(pcr + bytes.fromhex(hash_hex)).digest()


def calcular_pcr(hashes_en_orden):
    pcr = bytes(32)  # estado inicial: 32 bytes en cero
    for h in hashes_en_orden:
        pcr = extender(pcr, h)
    return pcr.hex()


def leer_eventlog(ruta):
    eventos = []
    with open(ruta) as f:
        for linea in f:
            partes = linea.split()
            if len(partes) == 2:
                eventos.append((partes[0], partes[1].lower()))
    return eventos


def linea(estado, texto, color):
    print(f"  {texto:<46} {color}{estado}{FIN}")


# ---------- subcomandos ----------
def cmd_nonce(args):
    nonce = secrets.token_hex(16)  # 16 bytes aleatorios, de un solo uso
    with open(args.guardar, "w") as f:
        f.write(nonce + "\n")
    print(nonce)


def cmd_golden(args):
    hashes = {}
    for nombre in args.orden:
        ruta = os.path.join(args.dir, nombre)
        if not os.path.isfile(ruta):
            sys.exit(f"Falta el componente de referencia: {ruta}")
        hashes[nombre] = sha256_archivo(ruta)
    golden = {"pcr": PCR_INDEX, "orden": args.orden, "hashes": hashes}
    with open(args.out, "w") as f:
        json.dump(golden, f, indent=2)
    print(f"Golden values guardados en {args.out}:")
    for n, h in hashes.items():
        print(f"  {n:<15} {h}")
    print(f"  PCR {PCR_INDEX} esperado: {calcular_pcr([hashes[n] for n in args.orden])}")


def correr_checkquote(ak_pub, dir_salida, nonce):
    """Devuelve (ok, motivo, pcr_hex)."""
    ruta = lambda n: os.path.join(dir_salida, n)
    for n in ("quote.msg", "quote.sig", "quote.pcrs"):
        if not os.path.isfile(ruta(n)):
            return False, f"Falta el archivo {ruta(n)}", None
    cmd = ["tpm2_checkquote", "-u", ak_pub, "-m", ruta("quote.msg"), "-s", ruta("quote.sig"),
           "-f", ruta("quote.pcrs"), "-g", "sha256", "-q", nonce]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        err = (r.stderr or "").lower()
        if "nonce" in err:
            motivo = "el nonce del quote NO coincide con el que envió el verificador (posible quote reutilizado)"
        elif "signature" in err:
            motivo = "la firma del quote NO es válida para la AK conocida"
        else:
            motivo = "tpm2_checkquote falló: " + (r.stderr.strip().splitlines() or ["error desconocido"])[-1]
        return False, motivo, None
    m = re.search(rf"^\s*{PCR_INDEX}:\s*0x([0-9a-fA-F]{{64}})", r.stdout, re.MULTILINE)
    if not m:
        return False, "no se pudo leer el PCR 16 dentro del quote", None
    return True, "", m.group(1).lower()


def cmd_verificar(args):
    print(f"{NEGRITA}== VERIFICADOR =={FIN}")
    print(f"Nonce enviado: {args.nonce}")

    with open(args.golden) as f:
        golden = json.load(f)
    orden = golden["orden"]
    golden_hashes = golden["hashes"]

    # 1) Firma + nonce + consistencia del quote
    ok, motivo, pcr_quote = correr_checkquote(args.ak, args.dir, args.nonce)
    if not ok:
        linea("FALLÓ", "1. Firma y nonce del quote", ROJO)
        print(f"\n  Motivo: {motivo}")
        print(f"\n{ROJO}{NEGRITA}RESULTADO: NO CONFIABLE{FIN}")
        return 1
    linea("OK", "1. Firma de la AK y nonce del quote", VERDE)

    # 2) Valor esperado a partir de los golden values
    pcr_esperado = calcular_pcr([golden_hashes[n] for n in orden])
    print(f"  PCR {PCR_INDEX} del quote   : {pcr_quote}")
    print(f"  PCR {PCR_INDEX} esperado    : {pcr_esperado}")

    if pcr_quote == pcr_esperado:
        linea("COINCIDE", "2. PCR del quote vs golden values", VERDE)
        print(f"\n{VERDE}{NEGRITA}RESULTADO: CONFIABLE{FIN}")
        return 0
    linea("DIFERENTE", "2. PCR del quote vs golden values", ROJO)

    # 3) Diagnóstico con el registro de eventos
    print("\n  Diagnóstico con el registro de eventos:")
    ruta_log = os.path.join(args.dir, "eventlog.txt")
    if not os.path.isfile(ruta_log):
        print(f"  - No hay registro de eventos ({ruta_log}); no se puede señalar el componente.")
        print(f"\n{ROJO}{NEGRITA}RESULTADO: NO CONFIABLE{FIN}")
        return 1

    eventos = leer_eventlog(ruta_log)
    pcr_log = calcular_pcr([h for _, h in eventos])
    if pcr_log != pcr_quote:
        print(f"  - {AMARILLO}El registro de eventos NO reproduce el PCR firmado.{FIN}")
        print(f"    PCR reconstruido desde el log: {pcr_log}")
        print("    El log fue manipulado o está incompleto: no se puede confiar en él")
        print("    para señalar el componente.")
        print(f"\n{ROJO}{NEGRITA}RESULTADO: NO CONFIABLE (registro de eventos inconsistente){FIN}")
        return 1
    print(f"  - {VERDE}El log reproduce el PCR firmado: es auténtico.{FIN}")

    culpables = []
    nombres_log = [n for n, _ in eventos]
    for n, h in eventos:
        if n not in golden_hashes:
            print(f"  - {ROJO}Componente inesperado en el arranque: {n}{FIN}")
            culpables.append(n)
        elif h != golden_hashes[n]:
            print(f"  - {ROJO}{n}: NO coincide{FIN}")
            print(f"      obtenido: {h}")
            print(f"      esperado: {golden_hashes[n]}")
            culpables.append(n)
    for n in orden:
        if n not in nombres_log:
            print(f"  - {ROJO}Componente que no se midió: {n}{FIN}")
            culpables.append(n)
    if not culpables and nombres_log != [n for n in orden if n in nombres_log]:
        print(f"  - {ROJO}Los componentes se midieron en un orden distinto al esperado.{FIN}")
        culpables.append("orden de arranque")

    detalle = ", ".join(culpables) if culpables else "causa no determinada"
    print(f"\n{ROJO}{NEGRITA}RESULTADO: NO CONFIABLE  (componente: {detalle}){FIN}")
    return 1


# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Verificador de atestación (Proyecto 2)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("nonce", help="genera un nonce aleatorio")
    s.add_argument("--guardar", default="nonce.txt")
    s.set_defaults(func=cmd_nonce)

    s = sub.add_parser("golden", help="calcula los golden values de una carpeta de referencia")
    s.add_argument("--dir", default="componentes_buenos")
    s.add_argument("--out", default="golden.json")
    s.add_argument("--orden", nargs="+", default=ORDEN_DEFAULT)
    s.set_defaults(func=cmd_golden)

    s = sub.add_parser("verificar", help="verifica un quote")
    s.add_argument("--nonce", required=True, help="nonce que el verificador envió")
    s.add_argument("--dir", default="salida", help="carpeta con quote.msg, quote.sig, quote.pcrs, eventlog.txt")
    s.add_argument("--ak", default="claves/ak.pub", help="llave pública de la AK")
    s.add_argument("--golden", default="golden.json")
    s.set_defaults(func=cmd_verificar)

    args = ap.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
