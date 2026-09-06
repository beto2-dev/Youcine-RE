# 3. Protecciones y bypass (actualizado 2026-09-07)

Este documento es el mapa completo del stack de protecciones de iJiami
encontrado en YouCine 1.17.6 (`ycMob_1.17.6_ycsite.apk`) y el bypass de
cada capa, establecido empíricamente durante las ejecuciones de GitHub
Actions de este repositorio. Cada afirmación está respaldada por un log
de ejecución (historial privado de Actions) y por artefactos en
`evidence/`.

## 3.1 El packer

| Propiedad | Valor |
|---|---|
| Vendor | iJiami (AiJiami / 爱加密) |
| String de compilador | `ijiami SecLLVM compiler 1.7.4.20` (dentro de `libexec.so`) |
| Stub DEX | 13.608 bytes, solo `s.h.e.l.l.{S,A,N,C}` |
| Payload cifrado | `assets/ijiami.dat`, 9.543.463 bytes, 4 DEX |
| Loader nativo | `assets/ijm_lib/<abi>/libexec.so` + `libexecmain.so` (4 ABIs) |
| Cifrado de datos | `com.ijm.dataencryption.DETool` + `libijmDataEncryption*.so` |
| Integridad | `assets/signed.bin` + `libed25519.so` |
| Application real | `com.mobile.brasiltv.app.App` (linaje Magis/Xuper/Brasil TV) |

El stub selecciona la ABI así (reconstruido a partir del `S.java` /
`N.java` decompilados en `evidence/stub/`):

```java
String linkerArch = ld();                    // ELF e_machine de /system/bin/linker(64)
String abis      = a();                      // reflexión de Build.SUPPORTED_ABIS
if (linkerArch.contains("x86")) {
    extract(il() ? "x86_64" : "x86");        // proceso de 64 bits -> x86_64
} else {
    extract(il() ? "arm64-v8a" : "armeabi"); // il(): /proc/self/maps contiene /lib64/
}
```

El inicializador estático de `N` ejecuta
`System.load(filesDir + "/libexec.so")` y
`System.load(filesDir + "/libexecmain.so")`, y el descifrado real ocurre
en el método nativo `s.h.e.l.l.N.al(...)`, invocado por
`A.instantiateApplication()` para reemplazar el classloader antes de
instanciar la `Application` real.

## 3.2 Hallazgos capa por capa y contramedidas

### L1 - Selección de ABI / proceso (la trampa de traducción)

**Hallazgo.** En un emulador x86_64 con `ndk_translation`, instalar la
APK original asigna `primaryCpuAbi=arm64-v8a` (la APK solo trae
`lib/armeabi-v7a` y `lib/arm64-v8a`). El proceso es **un proceso ARM
completo** forkeado desde `/system/bin/arm/app_process`; bionic resuelve
las librerías del sistema desde `/system/lib/arm/`. Dos consecuencias:

* El build x86 de `libexec.so` es rechazado por el linker:
  `dlopen failed: ".../files/libexec.so" is for EM_386 (3) instead of
  EM_ARM (40)` (capturado con `setprop debug.ld.app.<pkg> dlopen`).
* El build arm64 de `libexec.so` carga, pero **el código auto-modificable
  de SecLLVM no sobrevive a la traducción binaria**, por lo que el
  registro JNI de `s.h.e.l.l.N.al` nunca ocurre y el stub muere con
  `UnsatisfiedLinkError`.

**Contramedida.** `unpack/make_dump_build.py` elimina `lib/arm*` para
que la app se instale sin ABI nativa y forkee desde el zygote x86_64 de
64 bits; el stub entonces extrae `ijm_lib/x86_64/libexec.so`, que corre
**nativamente** (probado: la traza de frida muestra `dlopen -> ok` para
ambas librerías y SELinux otorga `execute` sobre el app_data_file).

### L2 - Verificación de firma (anti-reempaquetado)

**Hallazgo.** iJiami verifica que la APK instalada sea *idéntica en
contenido* a la original empacada. Se probaron las tres vías siguientes
y las tres resultaron insuficientes:

1. Conservar los archivos v1 JAR originales
   (`META-INF/XXL-OTT.RSA/.SF/MANIFEST.MF`) en la dump-build re-firmada -
   el chequeo siguió fallando.
2. Falsificar el certificado registrado en PackageManager
   (`unpack/patch_packages_xml.py` transplanta el bloque `<sigs>`
   original en `/data/system/packages.xml` con el framework detenido) -
   el chequeo siguió fallando.
3. Reemplazar `kill`/`exit` a nivel de libc con frida - el suicidio se
   emite con **syscalls crudos** (ignora por completo los hooks de libc).

**Conclusión.** El gate es un chequeo a nivel de contenido (muy
probablemente el `signed.bin` firmado con ed25519 / un hash sobre la
APK), evaluado *antes* de que `N.al()` descifre algo. Una APK re-firmada
o modificada jamás llega al descifrado. Esta es la conclusión operativa
central del lab: **el unpacking dinámico de este packer requiere
ejecutar la APK original byte-exacta en un entorno ARM nativo.**

### L3 - La escalera de muerte anti-tamper

Cuando el chequeo falla, el packer recorre una escalera de escalonada.
Cada paso fue neutralizado en `unpack/trace_guard.c` (un supervisor
ptrace compilado con el NDK para x86_64 que se adjunta en milisegundos
a la aparición del proceso y sigue cada hilo e hijo forkeado):

| Paso | Mecanismo | Observado como | Contramedida |
|---|---|---|---|
| 1 | `kill(getpid(), SIGKILL)` syscall crudo | `neutralized kill syscall 62 (sig 9)` | reescribir el syscall a `getpid` a nivel de kernel |
| 2 | `exit`/`exit_group` syscall crudo | `neutralized exit syscall 60/231` | reescribir a `getpid` |
| 3 | trampas `int3` (sonda anti-debug) | `swallowed SIGTRAP (int3 probe)` x47 | suprimir la señal; la ejecución continúa tras el `int3` |
| 4 | instrucción ilegal `ud2` | 5,4M `suppressed fault signal 4` | leer la instrucción con PEEKDATA; en `0F 0B` avanzar RIP en 2 |
| 5 | SIGSEGV deliberado | `tracee gone (sig 11)` | retransmitirla es fatal (NO es un implicit-null-check de ART); suprimirla fija el hilo en un bucle de refault, vivo pero congelado |

Con toda la escalera bloqueada el proceso permanece vivo pero fijado
**antes** del descifrado - lo que confirma L2: no existe un
"forzar-continuar" que pase el gate de contenido.

### L4 - Sondas anti-debug

* `PTRACE_TRACEME` del tracee: falla bajo un tracer real. El guardián
  reescribe el syscall `ptrace` como `sched_yield`, que retorna 0 - la
  sonda cree que tuvo éxito.
* Hijos watchdog: los hijos forkeados se trazan automáticamente vía
  `PTRACE_O_TRACEFORK|TRACECLONE`.
* El dumper externo por `/proc/<pid>/mem` nunca se inyecta en el
  proceso, de modo que los escaneos de `/proc/self/maps` y `TracerPid`
  no encuentran nada.

### L5 - Requisitos del entorno

* El `libexecmain.so` de cada ABI declara `DT_NEEDED libstdc++.so`.
  Android 11 *sí* incluye un `libstdc++.so` público, así que no es
  bloqueante en el emulador (verificado en el run 34049784110), pero
  importa en sistemas más viejos/delgados.
* `System.load` desde `filesDir` funciona en API 30 con targetSdk 33
  (SELinux otorga `execute` sobre `app_data_file`; sin bloqueo W/X).

## 3.3 La estrategia que funciona

| Entorno | Resultado |
|---|---|
| Emulador x86_64 + APK original (cualquier ABI) | SecLLVM falla bajo ndk_translation - sin descifrado |
| Emulador x86_64 + dump-build + guardián completo | el loader corre nativo; el gate de contenido se niega a descifrar - callejón documentado |
| **Runner macOS arm64 (Apple Silicon) + TCG con `-accel off` + APK original** | **todo nativo y legítimo: los chequeos pasan, el descifrado procede** (pipeline final; ver 06-unpack-dinamico.md) |
| Runners Linux de GitHub + AVD arm64 | bloqueado por el launcher del emulador (`FATAL: Avd's CPU Architecture 'arm64' is not supported ... on x86_64 host`) |
| Runners macOS de GitHub con aceleración por defecto | sin entitlement de Hypervisor.framework (`HVF error: HV_UNSUPPORTED`) - hay que pasar `-accel off` |

## 3.4 Qué es client-side y qué protegen realmente las protecciones

Todo lo de este documento es **client-side** y fue mapeado, derrotado o
documentado. Lo que el packer protege en última instancia es la *ruta de
la clave de descifrado* más el contenido de `ijiami.dat`; una vez que la
app corre nativamente, los cuatro payloads DEX descifrados son
recuperables de la memoria del proceso con el dumper out-of-process
(`unpack/external_memdump.py`), que barre:

* mapeos anónimos y `[anon:dalvik-*]` (incluido el espacio de regiones
  de 1 GiB, leído en fragmentos de 64 MiB con solapamiento de 2 MiB),
* `[heap]`, `/memfd:*`, mapeos de dalvik-cache,
* cualquier región con la magia `dex\n<ver>\0` y cabecera sana.

La mitad server-side de la app (hosts del portal, EPG, derechos VIP,
kill-switch de actualización forzada) está listada en
05-cliente-vs-servidor.md y está fuera del alcance de cualquier
eliminación de packer.
