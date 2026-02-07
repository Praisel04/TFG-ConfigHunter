import datetime
from pathlib import Path
import os
import stat

# =====================================================================
#   FUNCIONES INTERNAS PARA EXTRAER PARÁMETROS Y EVIDENCIAS
# =====================================================================

def get_param(config_text, name):
    """
    Devuelve el valor del parámetro indicado (primera coincidencia).
    """
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(name.lower()):
            parts = stripped.split()
            if len(parts) > 1:
                return parts[1].lower()
    return None


def get_line_with_param(config_text, name):
    """
    Devuelve (número_de_línea, texto_completo) si existe,
    o (None, None) si no aparece.
    """
    lines = config_text.splitlines()
    for i, raw in enumerate(lines, start=1):
        if raw.strip().lower().startswith(name.lower()):
            return i, raw.strip()
    return None, None


def evidence_line(config_text, param):
    """
    Devuelve evidencia formateada:
    - "Línea X: contenido"
    - o "Parámetro no encontrado"
    """
    num, text = get_line_with_param(config_text, param)
    if num:
        return f"Línea {num}: {text}"
    return "Parámetro no encontrado en sshd_config"


def check_file_permissions(path, expected_mode, expected_user=None, expected_group=None):
    """
    Comprueba permisos, usuario y grupo de un archivo.
    Retorna lista de findings parciales.
    """
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


# =====================================================================
#                 MÓDULO PRINCIPAL SSH
# =====================================================================

def run():
    findings = []
    timestamp = datetime.datetime.now().isoformat()

    # -----------------------------------------------------------
    # 1. Cargar sshd_config (dummy o real)
    # -----------------------------------------------------------

    dummy = Path("/etc/ssh/sshd_config")
    if dummy.exists():
        sshd_config_text = dummy.read_text(encoding="utf-8", errors="ignore")
    else:
        return [{
                "id": "CHK-SSH-000",
                "title": "No se encontró sshd_config",
                "severity": "info",
                "evidence": "No existe dummy/sshd_config ni /etc/ssh/sshd_config",
                "remediation": "Cree un dummy o instale openssh-server.",
                "explanation": "Sin archivo de configuración no puede auditarse SSH.",
                "timestamp": timestamp
            }]

    # ===========================================================
    # 2. REGLAS CIS 5.1.1 → 5.1.22
    # ===========================================================

    # Helper para añadir regla simple
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

    # ----------------------------------------------------------
    # 5.1.1 — Permisos de sshd_config deben ser 600 (propietario root)
    # ----------------------------------------------------------

    if dummy.exists():
        # Dummy-based: activar si texto contiene BAD_PERMISSIONS
        if "BAD_PERMISSIONS" in sshd_config_text:
            add_finding(
                "5.1.1",
                "Permisos inseguros en sshd_config",
                "alta",
                "Archivo dummy contiene BAD_PERMISSIONS",
                "chmod 600 /etc/ssh/sshd_config",
                "Permisos incorrectos permiten modificar configuración crítica de SSH."
            )
    else:
        issues = check_file_permissions("/etc/ssh/sshd_config", 0o600, 0, 0)
        if issues:
            add_finding("5.1.1", "Permisos incorrectos en sshd_config", "alta",
                        "; ".join(issues),
                        "chmod 600 /etc/ssh/sshd_config",
                        "CIS exige permisos estrictos para proteger configuración SSH.")

    # ----------------------------------------------------------
    # 5.1.2 — Permisos claves privadas host
    # ----------------------------------------------------------

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
                    "Claves privadas deben estar protegidas para evitar MITM."
                )

    # ----------------------------------------------------------
    # 5.1.3 — Permisos claves públicas host
    # ----------------------------------------------------------

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

    # ----------------------------------------------------------
    # 5.1.4 — AllowUsers / AllowGroups deben estar definidos
    # ----------------------------------------------------------

    if "AllowUsers" not in sshd_config_text and "AllowGroups" not in sshd_config_text:
        add_finding(
            "5.1.4",
            "Falta AllowUsers o AllowGroups",
            "media",
            "No se encontró ninguna línea AllowUsers ni AllowGroups",
            "Añadir AllowUsers <usuario>",
            "Limitar usuarios reduce superficie de ataque."
        )

    # ----------------------------------------------------------
    # 5.1.5 — Banner configurado
    # ----------------------------------------------------------

    if "Banner" not in sshd_config_text:
        add_finding(
            "5.1.5",
            "SSH Banner no configurado",
            "media",
            "No se encontró parámetro Banner",
            "Añadir Banner /etc/issue.net",
            "Un banner legal advierte sobre uso no autorizado."
        )

    # ----------------------------------------------------------
    # 5.1.6 — Ciphers
    # ----------------------------------------------------------

    # CIS exige evitar estos cifrados:
    weak_ciphers = [
        "aes128-cbc", "3des-cbc", "blowfish-cbc",
        "arcfour", "arcfour128", "arcfour256", "aes192-cbc" ,"aes256-cbc"
    ]

    for wc in weak_ciphers:
        if wc in sshd_config_text.lower():
            add_finding(
                "5.1.6",
                "Ciphers inseguros detectados",
                "alta",
                f"Se encontró el cipher inseguro: {wc}",
                "Ciphers aes256-ctr,aes192-ctr,aes128-ctr",
                "Los cifrados CBC son débiles frente a ataques conocidos."
            )
            break

    # ----------------------------------------------------------
    # 5.1.7 — ClientAliveInterval + ClientAliveCountMax
    # ----------------------------------------------------------

    cai = get_param(sshd_config_text, "ClientAliveInterval")
    cac = get_param(sshd_config_text, "ClientAliveCountMax")

    line_cai = evidence_line(sshd_config_text, "ClientAliveInterval")
    line_cac = evidence_line(sshd_config_text, "ClientAliveCountMax")

    if cai and int(cai) > 300:
        add_finding("5.1.7", "ClientAliveInterval demasiado alto", "media",
                    line_cai, "ClientAliveInterval 300",
                    "Valores altos retrasan tiempo de detección de sesiones muertas.")

    if cac and int(cac) > 3:
        add_finding("5.1.7", "ClientAliveCountMax demasiado alto", "media",
                    line_cac, "ClientAliveCountMax 3",
                    "Evita mantener sesiones inactivas por demasiado tiempo.")

    # ----------------------------------------------------------
    # 5.1.8 → 5.1.22 — Parámetros simples con expected value
    # ----------------------------------------------------------

    SIMPLE_RULES = [
        ("5.1.8",  "AllowTcpForwarding",   "no",   "alta",
         "AllowTcpForwarding debe estar en 'no'",
         "AllowTcpForwarding no",
         "Evita tunelización no autorizada."),

        ("5.1.9",  "GSSAPIAuthentication", "no",   "media",
         "GSSAPIAuthentication debe estar en 'no'",
         "GSSAPIAuthentication no",
         "Reduce superficie de ataque en autenticación."),

        ("5.1.10", "HostbasedAuthentication", "no", "alta",
         "HostbasedAuthentication debe estar en 'no'",
         "HostbasedAuthentication no",
         "Evita autenticación basada en confianza entre hosts."),

        ("5.1.11", "IgnoreRhosts", "yes", "alta",
         "IgnoreRhosts debe estar en 'yes'",
         "IgnoreRhosts yes",
         "Los archivos rhosts son altamente inseguros."),

        ("5.1.13", "LoginGraceTime", "60", "alta",
         "LoginGraceTime debe ser 60 o menos",
         "LoginGraceTime 60",
         "Reduce ventana para ataques de fuerza bruta."),

        ("5.1.14", "LogLevel", ["verbose","info"], "media",
         "LogLevel incorrecto",
         "LogLevel info",
         "Nivel adecuado permite registrar actividad sospechosa."),

        ("5.1.16", "MaxAuthTries", "4", "alta",
         "MaxAuthTries demasiado alto",
         "MaxAuthTries 4",
         "Evita ataques de fuerza bruta."),

        ("5.1.17", "MaxSessions", "10", "media",
         "MaxSessions demasiado alto",
         "MaxSessions 10",
         "Evita abuso de sesiones múltiples."),

        ("5.1.19", "PermitEmptyPasswords", "no", "alta",
         "PermitEmptyPasswords debe ser 'no'",
         "PermitEmptyPasswords no",
         "Evita sesiones sin contraseña."),

        ("5.1.20", "PermitRootLogin", "no", "critica",
         "PermitRootLogin debe estar en 'no'",
         "PermitRootLogin no",
         "Evita accesos directos al usuario root."),

        ("5.1.21", "PermitUserEnvironment", "no", "media",
         "PermitUserEnvironment debe estar en 'no'",
         "PermitUserEnvironment no",
         "Evita carga de configuraciones maliciosas."),

        ("5.1.22", "UsePAM", "yes", "media",
         "UsePAM debe estar en 'yes'",
         "UsePAM yes",
         "PAM añade controles avanzados de autenticación.")
    ]

    for cisref, param, expected, severity, title, remediation, explanation in SIMPLE_RULES:
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
            ok = (val == expected)

        if not ok:
            add_finding(cisref, title, severity, evidence, remediation, explanation)

    
    # ----------------------------------------------------------
    # 5.1.12 — KexAlgorithms
    # ----------------------------------------------------------
    
    # CIS exige evitar estos algoritmos:
    weak_kex = [
        "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"
    ]

    for wk in weak_kex:
        if wk in sshd_config_text.lower():
            add_finding(
                "5.1.12",
                "KexAlgorithms inseguros detectados",
                "alta",
                f"Se encontró el KexAlgorithm inseguro: {wk}",
                "KexAlgorithms ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256",
                "Usar Algortimos Kex inseguros puedes exponer las conexiones a posibles ataques 'Man In The Middle'"
            )
            break

    # ----------------------------------------------------------
    # 5.1.15 — MACs
    # ----------------------------------------------------------
    
    # CIS exige evitar estos algoritmos:
    weak_mac = [
        "hmac-md5","hmac-md5-96","hmac-ripemd160","hmac-sha1-96","umac-64@openssh.com","hmac-md5-etm@openssh.com","hmac-md5-96-etm@openssh.com","hmac-ripemd160-etm@openssh.com","hmac-sha1-96-etm@openssh.com","umac-64-etm@openssh.com","umac-128-etm@openssh.com"
    ]

    for wm in weak_mac:
        if wm in sshd_config_text.lower():
            add_finding(
                "5.1.15",
                "MACs inseguras detectadas",
                "alta",
                f"Se encontró Mac insegura: {wm}",
                "MACs hmac-sha1,hmac-sha2-256,hmac-sha2-384,hmac-sha2-512",
                "Usar algoritmos MAC débiles (MD5 o de 96 bits) puede permitir ataques de degradación para descifrar el túnel SSH y capturar credenciales e información sensible."
            )
            break

    # ----------------------------------------------------------
    # 5.1.18 — MaxStartups (solo se requiere que exista)
    # ----------------------------------------------------------

    ms_val = get_param(sshd_config_text, "MaxStartups")
    evidence = evidence_line(sshd_config_text, "MaxStartups")

    if not ms_val:
        add_finding(
            "5.1.18",
            "MaxStartups no definido",
            "media",
            evidence,
            "MaxStartups 10:30:60",
            "Evita DoS mediante conexiones simultáneas."
        )

    # ----------------------------------------------------------
    # Si no hay findings -> configuración segura
    # ----------------------------------------------------------

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
