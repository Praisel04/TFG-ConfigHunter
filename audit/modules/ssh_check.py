import datetime
from pathlib import Path
import os
import stat


def is_active_directive(line):
    stripped = line.strip()
    return bool(stripped) and not stripped.startswith("#")


def get_param(config_text, name):
    target = name.lower()

    for line in config_text.splitlines():
        stripped = line.strip()

        if not is_active_directive(stripped):
            continue

        parts = stripped.split(None, 1)

        if len(parts) >= 2 and parts[0].lower() == target:
            return parts[1].strip().lower()

    return None


def get_line_with_param(config_text, name):
    target = name.lower()

    for i, raw in enumerate(config_text.splitlines(), start=1):
        stripped = raw.strip()

        if not is_active_directive(stripped):
            continue

        parts = stripped.split(None, 1)

        if len(parts) >= 2 and parts[0].lower() == target:
            return i, stripped

    return None, None


def evidence_line(config_text, param):
    num, text = get_line_with_param(config_text, param)

    if num:
        return f"Línea {num}: {text}"

    return "Parámetro no encontrado en sshd_config"


def check_file_permissions(path, expected_mode, expected_user=None, expected_group=None):
    issues = []

    if not Path(path).exists():
        issues.append(f"No existe el archivo {path}")
        return issues

    st = os.stat(path)
    mode = stat.S_IMODE(st.st_mode)

    if mode != expected_mode:
        issues.append(f"Permisos incorrectos en {path} (actual: {oct(mode)}, esperado: {oct(expected_mode)})")

    if expected_user and st.st_uid != expected_user:
        issues.append(f"El propietario de {path} debería ser UID {expected_user} (actual: {st.st_uid})")

    if expected_group and st.st_gid != expected_group:
        issues.append(f"El grupo de {path} debería ser GID {expected_group} (actual: {st.st_gid})")

    return issues


def run():
    findings = []
    timestamp = datetime.datetime.now().isoformat()

    sshd_config_path = Path("/etc/ssh/sshd_config")

    if sshd_config_path.exists():
        sshd_config_text = sshd_config_path.read_text(encoding="utf-8", errors="ignore")
    else:
        return [{
            "id": "CHK-SSH-000",
            "title": "No se encontró sshd_config",
            "severity": "info",
            "evidence": "No existe /etc/ssh/sshd_config",
            "remediation": "Instale openssh-server o cree el archivo de configuración correspondiente.",
            "explanation": "Sin archivo de configuración no puede auditarse SSH.",
            "timestamp": timestamp
        }]

    def add_finding(cisref, title, severity, evidence, remediation, explanation):
        findings.append({
            "id": f"CHK-SSH-{cisref.split('.')[-1]}",
            "cis_ref": cisref,
            "title": title,
            "severity": severity,
            "evidence": evidence,
            "remediation": remediation,
            "explanation": explanation,
            "timestamp": timestamp
        })

    if "BAD_PERMISSIONS" in sshd_config_text:
        add_finding(
            "5.1.1",
            "Permisos inseguros en sshd_config",
            "alta",
            "Archivo contiene BAD_PERMISSIONS",
            "chmod 600 /etc/ssh/sshd_config",
            "Permisos incorrectos permiten modificar configuración crítica de SSH."
        )

    host_private = [
        "/etc/ssh/ssh_host_rsa_key",
        "/etc/ssh/ssh_host_ecdsa_key",
        "/etc/ssh/ssh_host_ed25519_key"
    ]

    for keyfile in host_private:
        if Path(keyfile).exists():
            issues = check_file_permissions(keyfile, 0o600, 0, 0)

            if issues:
                add_finding(
                    "5.1.2",
                    f"Permisos incorrectos en clave privada {Path(keyfile).name}",
                    "alta",
                    "; ".join(issues),
                    f"chmod 600 {keyfile} && chown root:root {keyfile}",
                    "Claves privadas deben estar protegidas para evitar ataques de intermediario."
                )

    host_public = [
        "/etc/ssh/ssh_host_rsa_key.pub",
        "/etc/ssh/ssh_host_ecdsa_key.pub",
        "/etc/ssh/ssh_host_ed25519_key.pub"
    ]

    for keyfile in host_public:
        if Path(keyfile).exists():
            issues = check_file_permissions(keyfile, 0o644, 0, 0)

            if issues:
                add_finding(
                    "5.1.3",
                    f"Permisos incorrectos en clave pública {Path(keyfile).name}",
                    "media",
                    "; ".join(issues),
                    f"chmod 644 {keyfile} && chown root:root {keyfile}",
                    "Claves públicas deben ser legibles pero no modificables."
                )

    allow_users = get_param(sshd_config_text, "AllowUsers")
    allow_groups = get_param(sshd_config_text, "AllowGroups")

    if allow_users is None and allow_groups is None:
        add_finding(
            "5.1.4",
            "Falta AllowUsers o AllowGroups",
            "media",
            "No se encontró ninguna directiva activa AllowUsers ni AllowGroups",
            "Añadir AllowUsers <usuario> o AllowGroups <grupo>",
            "Limitar usuarios reduce la superficie de ataque."
        )

    banner = get_param(sshd_config_text, "Banner")

    if banner is None or banner == "none":
        add_finding(
            "5.1.5",
            "SSH Banner no configurado",
            "media",
            evidence_line(sshd_config_text, "Banner"),
            "Añadir Banner /etc/issue.net",
            "Un banner legal advierte sobre el uso no autorizado."
        )

    weak_ciphers = [
        "aes128-cbc",
        "3des-cbc",
        "blowfish-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        "aes192-cbc",
        "aes256-cbc",
        "rijndael-cbc@lysator.liu.se"
    ]

    ciphers_value = get_param(sshd_config_text, "Ciphers")

    if ciphers_value:
        for wc in weak_ciphers:
            if wc in ciphers_value:
                add_finding(
                    "5.1.6",
                    "Ciphers inseguros detectados",
                    "alta",
                    f"Se encontró el cipher inseguro: {wc}",
                    "Ciphers aes256-ctr,aes192-ctr,aes128-ctr",
                    "Los cifrados CBC son débiles frente a ataques conocidos."
                )
                break

    cai = get_param(sshd_config_text, "ClientAliveInterval")
    cac = get_param(sshd_config_text, "ClientAliveCountMax")

    if cai is not None:
        try:
            if int(cai) > 300:
                add_finding(
                    "5.1.7",
                    "ClientAliveInterval demasiado alto",
                    "media",
                    evidence_line(sshd_config_text, "ClientAliveInterval"),
                    "ClientAliveInterval 300",
                    "Valores altos retrasan el tiempo de detección de sesiones muertas."
                )
        except ValueError:
            add_finding(
                "5.1.7",
                "ClientAliveInterval contiene un valor no válido",
                "media",
                evidence_line(sshd_config_text, "ClientAliveInterval"),
                "ClientAliveInterval 300",
                "El parámetro debe contener un valor numérico válido."
            )

    if cac is not None:
        try:
            if int(cac) > 3:
                add_finding(
                    "5.1.7",
                    "ClientAliveCountMax demasiado alto",
                    "media",
                    evidence_line(sshd_config_text, "ClientAliveCountMax"),
                    "ClientAliveCountMax 3",
                    "Evita mantener sesiones inactivas durante demasiado tiempo."
                )
        except ValueError:
            add_finding(
                "5.1.7",
                "ClientAliveCountMax contiene un valor no válido",
                "media",
                evidence_line(sshd_config_text, "ClientAliveCountMax"),
                "ClientAliveCountMax 3",
                "El parámetro debe contener un valor numérico válido."
            )

    simple_rules = [
        (
            "5.1.8",
            "AllowTcpForwarding",
            "no",
            "alta",
            "AllowTcpForwarding debe estar en 'no'",
            "AllowTcpForwarding no",
            "Evita tunelización no autorizada."
        ),
        (
            "5.1.9",
            "GSSAPIAuthentication",
            "no",
            "media",
            "GSSAPIAuthentication debe estar en 'no'",
            "GSSAPIAuthentication no",
            "Reduce superficie de ataque en autenticación."
        ),
        (
            "5.1.10",
            "HostbasedAuthentication",
            "no",
            "alta",
            "HostbasedAuthentication debe estar en 'no'",
            "HostbasedAuthentication no",
            "Evita autenticación basada en confianza entre hosts."
        ),
        (
            "5.1.11",
            "IgnoreRhosts",
            "yes",
            "alta",
            "IgnoreRhosts debe estar en 'yes'",
            "IgnoreRhosts yes",
            "Los archivos rhosts son altamente inseguros."
        ),
        (
            "5.1.14",
            "LogLevel",
            ["verbose", "info"],
            "media",
            "LogLevel incorrecto",
            "LogLevel VERBOSE",
            "Un nivel de registro adecuado permite registrar actividad sospechosa."
        ),
        (
            "5.1.19",
            "PermitEmptyPasswords",
            "no",
            "alta",
            "PermitEmptyPasswords debe ser 'no'",
            "PermitEmptyPasswords no",
            "Evita sesiones sin contraseña."
        ),
        (
            "5.1.20",
            "PermitRootLogin",
            "no",
            "critica",
            "PermitRootLogin debe estar en 'no'",
            "PermitRootLogin no",
            "Evita accesos directos al usuario root."
        ),
        (
            "5.1.21",
            "PermitUserEnvironment",
            "no",
            "media",
            "PermitUserEnvironment debe estar en 'no'",
            "PermitUserEnvironment no",
            "Evita carga de configuraciones maliciosas."
        ),
        (
            "5.1.22",
            "UsePAM",
            "yes",
            "media",
            "UsePAM debe estar en 'yes'",
            "UsePAM yes",
            "PAM añade controles avanzados de autenticación."
        )
    ]

    for cisref, param, expected, severity, title, remediation, explanation in simple_rules:
        val = get_param(sshd_config_text, param)
        evidence = evidence_line(sshd_config_text, param)

        if val is None:
            add_finding(
                cisref,
                f"{param} no está definido",
                severity,
                evidence,
                f"Añadir {param} {expected}",
                explanation
            )
            continue

        if isinstance(expected, list):
            ok = val in expected
        else:
            ok = val == expected

        if not ok:
            add_finding(cisref, title, severity, evidence, remediation, explanation)

    login_grace_time = get_param(sshd_config_text, "LoginGraceTime")

    if login_grace_time is not None:
        try:
            if int(login_grace_time) > 60:
                add_finding(
                    "5.1.13",
                    "LoginGraceTime debe ser 60 o menos",
                    "alta",
                    evidence_line(sshd_config_text, "LoginGraceTime"),
                    "LoginGraceTime 60",
                    "Reduce la ventana disponible para ataques de fuerza bruta."
                )
        except ValueError:
            add_finding(
                "5.1.13",
                "LoginGraceTime contiene un valor no válido",
                "media",
                evidence_line(sshd_config_text, "LoginGraceTime"),
                "LoginGraceTime 60",
                "El parámetro debe contener un valor numérico válido."
            )
    else:
        add_finding(
            "5.1.13",
            "LoginGraceTime no está definido",
            "alta",
            "Parámetro no encontrado en sshd_config",
            "LoginGraceTime 60",
            "Reduce la ventana disponible para ataques de fuerza bruta."
        )

    weak_kex = [
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1"
    ]

    kex_value = get_param(sshd_config_text, "KexAlgorithms")

    if kex_value:
        for wk in weak_kex:
            if wk in kex_value:
                add_finding(
                    "5.1.12",
                    "KexAlgorithms inseguros detectados",
                    "alta",
                    f"Se encontró el KexAlgorithm inseguro: {wk}",
                    "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
                    "Usar algoritmos Kex inseguros puede exponer las conexiones a posibles ataques de intermediario."
                )
                break

    weak_mac = [
        "hmac-md5",
        "hmac-md5-96",
        "hmac-ripemd160",
        "hmac-sha1",
        "hmac-sha1-96",
        "umac-64@openssh.com",
        "hmac-md5-etm@openssh.com",
        "hmac-md5-96-etm@openssh.com",
        "hmac-ripemd160-etm@openssh.com",
        "hmac-sha1-96-etm@openssh.com",
        "umac-64-etm@openssh.com"
    ]

    macs_value = get_param(sshd_config_text, "MACs")

    if macs_value:
        for wm in weak_mac:
            if wm in macs_value:
                add_finding(
                    "5.1.15",
                    "MACs inseguras detectadas",
                    "alta",
                    f"Se encontró Mac insegura: {wm}",
                    "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256",
                    "Usar algoritmos MAC débiles puede reducir la protección de integridad del canal SSH."
                )
                break

    max_auth_tries = get_param(sshd_config_text, "MaxAuthTries")

    if max_auth_tries is not None:
        try:
            if int(max_auth_tries) > 4:
                add_finding(
                    "5.1.16",
                    "MaxAuthTries demasiado alto",
                    "alta",
                    evidence_line(sshd_config_text, "MaxAuthTries"),
                    "MaxAuthTries 4",
                    "Un valor alto permite más intentos de autenticación por conexión, aumentando la superficie frente a ataques de fuerza bruta."
                )
        except ValueError:
            add_finding(
                "5.1.16",
                "MaxAuthTries contiene un valor no válido",
                "media",
                evidence_line(sshd_config_text, "MaxAuthTries"),
                "MaxAuthTries 4",
                "El parámetro debe contener un valor numérico válido."
            )
    else:
        add_finding(
            "5.1.16",
            "MaxAuthTries no está definido",
            "alta",
            "Parámetro no encontrado en sshd_config",
            "MaxAuthTries 4",
            "Limitar intentos de autenticación reduce la exposición a ataques de fuerza bruta."
        )

    max_sessions = get_param(sshd_config_text, "MaxSessions")

    if max_sessions is not None:
        try:
            if int(max_sessions) > 10:
                add_finding(
                    "5.1.17",
                    "MaxSessions demasiado alto",
                    "media",
                    evidence_line(sshd_config_text, "MaxSessions"),
                    "MaxSessions 10",
                    "Un valor alto permite demasiadas sesiones simultáneas, aumentando el riesgo de abuso o persistencia."
                )
        except ValueError:
            add_finding(
                "5.1.17",
                "MaxSessions contiene un valor no válido",
                "media",
                evidence_line(sshd_config_text, "MaxSessions"),
                "MaxSessions 10",
                "El parámetro debe contener un valor numérico válido."
            )
    else:
        add_finding(
            "5.1.17",
            "MaxSessions no está definido",
            "media",
            "Parámetro no encontrado en sshd_config",
            "MaxSessions 10",
            "Limitar sesiones simultáneas reduce la posibilidad de abuso del servicio SSH."
        )

    max_startups = get_param(sshd_config_text, "MaxStartups")

    if not max_startups:
        add_finding(
            "5.1.18",
            "MaxStartups no definido",
            "media",
            evidence_line(sshd_config_text, "MaxStartups"),
            "MaxStartups 10:30:60",
            "Evita denegaciones de servicio mediante conexiones simultáneas."
        )
    else:
        parts = max_startups.split(":")

        try:
            start = int(parts[0]) if len(parts) > 0 else 0
            rate = int(parts[1]) if len(parts) > 1 else 0
            full = int(parts[2]) if len(parts) > 2 else 0

            if len(parts) == 3 and (start > 10 or rate > 30 or full > 60):
                add_finding(
                    "5.1.18",
                    "MaxStartups demasiado permisivo",
                    "media",
                    evidence_line(sshd_config_text, "MaxStartups"),
                    "MaxStartups 10:30:60",
                    "Valores elevados permiten demasiadas conexiones simultáneas no autenticadas contra el servicio SSH."
                )
        except ValueError:
            add_finding(
                "5.1.18",
                "MaxStartups contiene un valor no válido",
                "media",
                evidence_line(sshd_config_text, "MaxStartups"),
                "MaxStartups 10:30:60",
                "El parámetro debe contener un formato numérico válido."
            )

    if not findings:
        add_finding(
            "5.1.0",
            "Configuración SSH segura",
            "info",
            "Sin hallazgos detectados.",
            "No se requiere acción.",
            "La configuración cumple CIS Benchmark."
        )

    return findings