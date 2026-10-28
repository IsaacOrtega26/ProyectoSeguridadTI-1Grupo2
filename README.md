# Proyecto 2 (Grupo 2): Arranque medido y atestación con TPM

Simulación de dos partes: una **máquina medida** que mide su "arranque" y firma un *quote*, y un **verificador** que decide si confía en ella.

Probado con `swtpm` + `tpm2-tools 5.6` en Ubuntu 24.04.

## Qué hay en la carpeta

| Archivo | Para qué sirve |
|---|---|
| `setup_tpm.sh` | Levanta el TPM simulado (swtpm) y crea la **EK** y la **AK** (una sola vez). |
| `preparar_demo.sh` | Crea los 4 archivos de prueba y los **golden values** (`golden.json`). |
| `medir_arranque.sh` | **Máquina medida**: mide, extiende en el PCR 16, escribe el event log y genera el quote. |
| `verificador.py` | **Verificador**: genera nonces, calcula golden values y responde CONFIABLE / NO CONFIABLE. |
| `demo.sh` | Corre las demos de clase (con pausas entre pasos). |
| `diagrama_atestacion.png / .svg` | Diagrama del flujo máquina ↔ verificador. |

## Instalación

```bash
sudo apt install swtpm swtpm-tools tpm2-tools openssl python3
```

## Uso rápido

```bash
chmod +x *.sh verificador.py
./demo.sh                  # pausa entre demos: Enter para avanzar
SIN_PAUSA=1 ./demo.sh      # todo de corrido
```

## Uso manual, paso a paso

```bash
./setup_tpm.sh             # TPM + EK + AK (idempotente)
./preparar_demo.sh         # archivos de prueba + golden.json

# 1) El VERIFICADOR genera el nonce
NONCE=$(python3 verificador.py nonce)

# 2) La MÁQUINA mide y firma el quote con ese nonce
./medir_arranque.sh "$NONCE"

# 3) El VERIFICADOR decide
python3 verificador.py verificar --nonce "$NONCE"
```

Para apagar el TPM simulado: `./setup_tpm.sh parar`.

## Guion de la exposición

Orden sugerido (unos 8 a 10 minutos con la teoría aparte):

1. **Diagrama** (`diagrama_atestacion.png`). Explica los tres mensajes: ① el verificador manda el nonce, ② la máquina devuelve el quote firmado, ③ y el registro de eventos.
2. **Demo 1, arranque limpio.** Muestra cómo cada componente se mide y se extiende en el PCR 16. El verificador responde **CONFIABLE** porque el PCR del quote es igual al calculado desde los golden values.
3. **Demo 2, rootkit simulado.** Se cambia **un solo byte** de `kernel.bin`. Muestra que el hash cambia por completo. El verificador responde **NO CONFIABLE** y señala `kernel.bin`.
   - Idea clave: la máquina *arrancó igual*. No hubo bloqueo (eso sería Secure Boot), pero quedó la evidencia (eso es Measured Boot).
4. **Demo 3, repetición.** Se reenvía el quote de la demo 1 (que era válido) contra un nonce nuevo. Falla por el nonce.
   - Idea clave: sin nonce, un atacante podría guardar un quote bueno y reenviarlo siempre.
5. **Demo 4 (extra).** El atacante edita `eventlog.txt` para ocultar el kernel. El verificador detecta que el log no reproduce el PCR firmado.
   - Idea clave: el log no es confiable por sí solo; lo valida el PCR firmado.

## Cómo cumple la consigna

| Requisito | Dónde |
|---|---|
| Medir 3 o 4 archivos con SHA-256 y extenderlos en el PCR 16, en orden | `medir_arranque.sh` |
| Quote firmado del PCR 16 | `medir_arranque.sh` (`tpm2_quote` con la AK y el nonce) |
| Golden values y PCR esperado | `verificador.py golden` / `calcular_pcr()` |
| Verificar firma del quote | `verificador.py` (`tpm2_checkquote`) |
| CONFIABLE / NO CONFIABLE señalando el componente | `verificador.py`, usando el event log |
| Demo 1: limpio | `demo.sh`, Demo 1 |
| Demo 2: un byte de `kernel.bin` | `demo.sh`, Demo 2 |
| Demo 3: quote viejo + nonce nuevo | `demo.sh`, Demo 3 |
| Diagrama del flujo | `diagrama_atestacion.png` |

## Preguntas que pueden hacer

- **¿Por qué el PCR 16 y no los PCR reales?** Los PCR 0 a 7 no se pueden reiniciar por software; el 16 es el de depuración. En un arranque real, cada componente iría a su PCR (firmware en 0, bootloader en 4, kernel en 9).
- **¿Por qué firmar con la AK y no con la EK?** La EK es una identidad única y permanente (rastreable) y normalmente solo descifra. La AK es una llave de firma que se puede renovar.
- **¿Qué pasa si el atacante edita el log?** Se reconstruye el PCR desde el log y no coincide con el del quote (Demo 4).
- **¿Y si el atacante también miente en el PCR?** No puede: el PCR va dentro del quote firmado por la AK, cuya llave privada nunca sale del TPM.
- **¿Qué impide un replay?** El nonce lo elige el verificador para cada consulta y va dentro de lo que firma el TPM.

## Limitaciones (conviene decirlas tú antes de que las pregunten)

- El verificador **confía en `ak.pub` sin comprobar que sea de un TPM legítimo**. En un sistema real se usa `tpm2_makecredential` / `tpm2_activatecredential` con el certificado de la EK.
- `swtpm` es un TPM por software; no tiene la protección de hardware de un TPM físico.
- Se simula con archivos de prueba y el PCR 16. No se miden el firmware ni el bootloader reales.
- Es una verificación puntual. Keylime, por ejemplo, consulta de forma continua y añade IMA para el tiempo de ejecución.

## Problemas frecuentes

- `No hay TPM disponible`: corre `./setup_tpm.sh`. Si reiniciaste la máquina, hay que volver a levantar swtpm.
- `out of memory for object contexts`: quedaron objetos cargados en el TPM; corre `tpm2_flushcontext -t` (con `export TPM2TOOLS_TCTI="swtpm:port=2321"`).
- Puerto 2321 ocupado: `./setup_tpm.sh parar` o revisa con `ss -ltnp | grep 2321`.
- Si tu `tpm2-tools` es la serie 4.x, algunas opciones pueden variar. Revisa la versión con `tpm2_quote --version`.

## Retos extra

1. **Por red.** Poner `verificador.py` como servidor (Flask) que entrega el nonce y recibe el quote, y la máquina medida como cliente.
2. **Comparar con un arranque real.** En una VM con vTPM: `tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements` y comparar con el PCR 0 a 9 de `tpm2_pcrread`.
3. **Registro de la AK.** Implementar `makecredential` / `activatecredential` para probar que la AK pertenece al mismo TPM que la EK.
