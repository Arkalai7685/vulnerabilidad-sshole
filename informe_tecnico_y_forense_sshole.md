# Informe Técnico y Análisis Forense (DFIR): Vulnerabilidad sshole (CVE-2026-123158)

**Autor:** Álvaro Manuel Castillo Arancibia  
**Especialidad:** Ingeniería en Ciberseguridad / Analista Programador  
**Laboratorio de Referencia:** TryHackMe — Reto Sherlock (`sshole`)  
**Identificador CVE:** CVE-2026-123158 (OpenSSH Authentication Bypass on musl libc)

---

## 1. Introducción al Problema

La vulnerabilidad **sshole (CVE-2026-123158)** representa un fallo crítico de bypass de autenticación en OpenSSH sobre sistemas operativos Linux ligeros que utilizan `musl libc` (como Alpine Linux) sin el uso de módulos PAM (*Pluggable Authentication Modules*). El problema surge de una colisión lógica cuando el demonio procesa contraseñas extremadamente largas (superiores a 256 caracteres): la función `crypt()` de `musl` devuelve un código de error estandarizado (`*`) al rechazar la longitud de la cadena, el cual colisiona directamente con los hashes de cuentas bloqueadas o deshabilitadas, permitiendo que un atacante salte la validación de credenciales y obtenga acceso interactivo no autorizado a través del puerto SSH.

---

## 2. Desarrollo de Preguntas Teóricas

### 2.1. Arquitectura y Dependencias

> **Pregunta:** *¿Qué combinación específica de componentes a nivel de sistema operativo y servicios de red (libc, gestor de autenticación y demonio SSH) es estrictamente necesaria para que un entorno sea vulnerable a sshole, y por qué los sistemas tradicionales basados en glibc con soporte PAM están exentos de este fallo?*

Para que un entorno sea vulnerable a **sshole (CVE-2026-123158)**, debe existir de forma simultánea la siguiente combinación de componentes:

1. **Biblioteca estándar de C (`musl libc`):** Utilizada de forma nativa en distribuciones minimalistas orientadas a contenedores (como Alpine Linux). Su implementación de la función `crypt(key, salt)` pone límite estricto de longitud de contraseña de **256 bytes** (`KEY_MAX`) y devuelve la cadena estática literal `"*"` ante cualquier condición de fallo.
2. **Ausencia de PAM en el flujo de autenticación (`UsePAM no` o compilación `--without-pam`):** Al no intervenir la capa de *Pluggable Authentication Modules*, el demonio `sshd` ejecuta directamente su función nativa `sys_auth_passwd()`, la cual consulta el archivo `/etc/shadow` y compara directamente el retorno de `crypt()` con el campo de contraseña del usuario.
3. **Demonio OpenSSH (`sshd`) con `PasswordAuthentication yes` y cuentas con marcador `*` en `/etc/shadow`:** El servidor debe permitir la autenticación basada en contraseñas y contar con cuentas en `/etc/shadow` cuyo campo de hash esté definido como `*`.

#### ¿Por qué los sistemas basados en `glibc` con soporte PAM están exentos?

* **Tokens de fallo anticolisión en `glibc` (`libxcrypt`):** Cuando la función `crypt()` en `glibc`/`libxcrypt` recibe un *salt* inválido (como `*` o `!`) o encuentra un error de procesamiento, nunca devuelve una cadena constante única. En su lugar, alterna dinámicamente entre dos tokens de fallo: devuelve `"*0"` si el *salt* de entrada no es `"*0"`, y devuelve `"*1"` si el *salt* de entrada es `"*0"`. Así, cuando el hash en `/etc/shadow` es `"*"`, `crypt()` retorna `"*0"`, garantizando que la comparación siempre falle (`strcmp("*0", "*") != 0`).
* **Validación previa en la capa PAM (`pam_unix.so`):** En sistemas tradicionales (Debian, Ubuntu, RHEL), OpenSSH delega la verificación a PAM. El módulo `pam_unix` inspecciona previamente el registro de `/etc/shadow` y rechaza cualquier cuenta marcada con `*` o `!` como bloqueada o inactiva antes de dar por válida una comparación de hashes.

| Componente / Criterio | Entorno Vulnerable (Alpine / musl) | Entorno Exento (Ubuntu, Debian, RHEL / glibc) |
| :--- | :--- | :--- |
| **Biblioteca C (`libc`)** | `musl libc` (límite de 256 bytes en `crypt()`) | `glibc` / `libxcrypt` |
| **Retorno de error en `crypt()`** | Cadena estática constante `"*"` | Token anticolisión dinámico (`"*0"` o `"*1"`) |
| **Gestor de Autenticación** | Rutina nativa `sys_auth_passwd()` (sin PAM) | Pila PAM (`pam_unix.so`) |
| **Evaluación con clave > 256 bytes** | `strcmp("*", "*") == 0` (**Bypass exitoso**) | `strcmp("*0", "*") != 0` (**Acceso rechazado**) |

---

### 2.2. Mecánica de la Colisión

> **Pregunta:** *Explique detalladamente cómo interactúan una contraseña de gran longitud, la gestión del salt criptográfico en OpenSSH y el manejo de errores de la función crypt() en musl para generar un falso positivo de autenticación.*

El falso positivo de autenticación se desencadena mediante una cadena lógica de cuatro etapas dentro del proceso de validación de OpenSSH:

1. **Estado del marcador en `/etc/shadow`:** En sistemas UNIX/Linux, el carácter `*` en el segundo campo de `/etc/shadow` (ej. `root:*:19600:0:99999:7:::`) se emplea para deshabilitar el acceso por contraseña de una cuenta, asumiendo que ningún algoritmo criptográfico (SHA-512, bcrypt, yescrypt) puede producir la cadena de un solo carácter `"*"` como salida válida.
2. **Paso del *salt* en OpenSSH (`sys_auth_passwd`):** Cuando el usuario intenta iniciar sesión, OpenSSH recupera la entrada de `/etc/shadow` del usuario solicitado y extrae su campo `pw_passwd` (cuyo valor es `"*"`), pasándolo directamente como el segundo argumento (`salt`) en la llamada `crypt(password, pw_passwd)`.
3. **Activación del error por longitud en `musl` (`> 256` caracteres):** El atacante envía una contraseña de más de 256 caracteres. Al ejecutarse `crypt(password, "*")` en `musl libc`, la función valida que la longitud de la contraseña no supere los 256 bytes antes de procesar el *salt*. Al exceder el límite, la función aborta la operación criptográfica y devuelve su cadena estática de error `"*"` (implementada así para evitar devolver `NULL` y prevenir cierres inesperados por *segmentation fault* en aplicaciones que pasan el retorno directamente a `strcmp()`).
4. **Colisión exacta y Falso Positivo:** OpenSSH recibe el retorno `encrypted_password = "*"` desde `crypt()` y ejecuta la comparación de validación contra el valor almacenado en `/etc/shadow` (`pw_passwd = "*"`):
   ```c
   if (strcmp(encrypted_password, pw_passwd) == 0) // strcmp("*", "*") == 0 -> TRUE
   ```
   Como ambas cadenas son idénticas byte a byte, OpenSSH interpreta que la contraseña proporcionada es correcta y concede acceso interactivo inmediato a la cuenta bloqueada.

---

### 2.3. Mitigación y Endurecimiento

> **Pregunta:** *Aparte de aplicar el parche oficial de actualización del paquete OpenSSH, mencione e instrumente al menos dos medidas de mitigación de defensa en profundidad a nivel de configuración que reduzcan drásticamente la superficie de exposición ante este vector de ataque.*

#### Medida 1: Deshabilitar la autenticación por contraseña en `/etc/ssh/sshd_config`

Al exigir exclusivamente autenticación mediante llaves públicas criptográficas, el demonio `sshd` nunca invoca `sys_auth_passwd()` ni la función `crypt()`, eliminando por completo el vector de entrada de la vulnerabilidad.

Instrumentación en `/etc/ssh/sshd_config`:
```ssh
# Deshabilitar autenticación basada en contraseñas
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no

# Forzar autenticación por llave pública y proteger root
PubkeyAuthentication yes
PermitRootLogin prohibit-password
```

Validación y recarga del servicio:
```bash
sshd -t && kill -HUP $(cat /var/run/sshd.pid)
```

#### Medida 2: Sustitución del marcador `*` por `!` en `/etc/shadow` y restricción de Shell

Dado que `musl` devuelve `"*"` en caso de error, cambiar el marcador de bloqueo de cuentas en `/etc/shadow` de `*` a `!` (o `!!`) impide la colisión lógica, puesto que `strcmp("*", "!")` siempre evalúa como falso. Complementariamente, asignar `/sbin/nologin` a las cuentas de sistema evita la obtención de una shell interactiva.

Instrumentación en consola o `Dockerfile`:
```bash
# 1. Reemplazar el marcador '*' por '!' en todas las cuentas de /etc/shadow
sed -i 's/^\([^:]*\):\*\(:.*\)/\1:!\2/' /etc/shadow

# 2. Bloquear explícitamente la cuenta root
passwd -l root

# 3. Restringir la shell de cuentas de servicio a /sbin/nologin
sed -i '/^root:/! s/\/bin\/ash$/\/sbin\/nologin/' /etc/passwd
```

---

## 3. Actividad Práctica: Análisis Forense de Incidente (Reto Sherlock - sshole)

> **Nota Metodológica y Justificación de Alcance:** El laboratorio forense **Sherlock (`sshole`)** de la plataforma TryHackMe requiere una suscripción comercial de pago (*TryHackMe Premium*) para desplegar la máquina virtual y descargar los artefactos propietarios, razón por la cual no es posible extraer capturas de pantalla directas desde una cuenta académica gratuita. En cumplimiento de los objetivos técnicos de la actividad, se presenta el análisis forense DFIR completo explicando las causas exactas del incidente, el comportamiento de los artefactos del sistema ante la explotación de **CVE-2026-123158** y el procedimiento analítico que ejecuta un especialista SOC/DFIR para investigar la intrusión.

### 3.1. Explicación Forense: ¿Por qué ocurrió el incidente?

El compromiso del contenedor se produce por una combinación crítica de valores por defecto al desplegar OpenSSH sobre **Alpine Linux**:

1. **Cuentas bloqueadas con `*` por defecto:** Al construir el contenedor, cuentas críticas como `root` o cuentas de servicio se crean sin una contraseña asignada, registrándose en `/etc/shadow` con el carácter `*` en el campo del hash (ej. `root:*:19600:0:99999:7:::`). En condiciones normales, esto inhabilita el inicio de sesión por contraseña porque ningún hash válido equivale a `"*"`.
2. **Exposición de `sys_auth_passwd()` sin PAM:** Como Alpine Linux prescinde de PAM por diseño para reducir el tamaño de la imagen y `sshd_config` mantenía habilitada la autenticación por contraseña (`PasswordAuthentication yes`), OpenSSH procesó directamente la entrada del atacante utilizando `crypt()` de `musl libc`.
3. **Ejecución del Bypass:** El atacante envió una petición de autenticación SSH hacia una cuenta con hash `*` suministrando una cadena de más de **256 caracteres** como contraseña. Al superar el límite de 256 bytes de `musl`, `crypt()` devolvió el código de error `"*"`. OpenSSH comparó dicho retorno con el `"*"` almacenado en `/etc/shadow`, validó erróneamente la identidad y abrió una sesión interactiva con privilegios del usuario objetivo.

### 3.2. Metodología de Investigación de Artefactos (SOC / DFIR)

#### Fase 1: Verificación Forense de la Configuración Vulnerable
El analista audita los archivos `/etc/shadow` y `/etc/ssh/sshd_config` dentro de la imagen forense del contenedor para demostrar qué cuentas eran explotables:

```bash
grep -E ':\*:' /etc/shadow
grep -iE 'PasswordAuthentication|PermitRootLogin|UsePAM' /etc/ssh/sshd_config
```

* **Indicador Forense:** La presencia de registros con `:*:` en `/etc/shadow` junto con `PasswordAuthentication yes` en `sshd_config` confirma la exposición directa al vector `CVE-2026-123158`.

#### Fase 2: Detección de la Intrusión en Registros SSH (`auth.log` / `messages`)
A continuación, se analizan los registros del demonio `sshd` en `/var/log/messages` o `/var/log/auth.log` para identificar el acceso no autorizado:

```bash
grep -iE "Accepted password|Failed password|session opened" /var/log/messages /var/log/auth.log 2>/dev/null
```

* **Indicador de Compromiso (IoC) en Logs:** A diferencia de un ataque de diccionario o fuerza bruta que genera múltiples eventos `Failed password`, la explotación de **sshole** produce un evento **`Accepted password for <usuario> from <IP_Atacante> port <Puerto> ssh2`** de forma directa al primer intento con un payload mayor a 256 bytes. Encontrar un evento `Accepted password` sobre una cuenta cuyo hash en `/etc/shadow` es `*` (y que por ende no tiene contraseña válida posible) demuestra de manera concluyente el abuso de la vulnerabilidad.

#### Fase 3: Reconstrucción Post-Explotación y Persistencia
Finalmente, el analista inspecciona los artefactos de actividad interactiva dentro del contenedor (considerando que Alpine Linux emplea `BusyBox ash` como shell predeterminada en lugar de `bash`):

```bash
cat /root/.ash_history /home/*/.ash_history 2>/dev/null
ls -la /root/.ssh/ /etc/crontabs/ /tmp/ /var/tmp/
```

* **Artefactos Analizados:**
  * **`.ash_history`:** Revela la secuencia exacta de comandos ejecutados por el atacante tras conseguir la shell (reconocimiento del sistema, lectura de archivos confidenciales o variables de entorno del contenedor).
  * **`/root/.ssh/authorized_keys` y `/etc/crontabs/root`:** Permiten identificar si el atacante instaló una llave pública SSH propia o programó tareas cron para mantener persistencia incluso si la contraseña o configuración del servicio fuera modificada posteriormente.

---

## 4. Conclusión

El análisis técnico y forense de **sshole (CVE-2026-123158)** evidencia cómo decisiones de diseño aparentemente inocentes en componentes independientes —el uso de `*` para cuentas sin contraseña en `/etc/shadow`, el retorno estático `"*"` de `crypt()` en `musl libc` ante claves mayores a 256 bytes y la ausencia de PAM en instalaciones ligeras de OpenSSH— pueden encadenarse para provocar un compromiso total de autenticación. Desde la perspectiva DFIR, la correlación entre el estado de `/etc/shadow` y los registros `Accepted password` de `sshd` permite detectar con certeza matemática este vector de intrusión, mientras que el endurecimiento proactivo de `sshd_config` (`PasswordAuthentication no`) y el uso del marcador `!` erradican por completo la superficie de ataque en entornos contenerizados.
