from pathlib import Path
import datetime
import re


def run():
    """
    Analiza sshd_config (dummy o real) buscando configuraciones inseguras.
    Devuelve una lista de hallazgos agrupados sin duplicados.
    """

    findings = []

    dummy_path = Path("dummy/sshd_config")
    real_path = Path("/etc/ssh/sshd_config")

    # --- Detectar archivo ---
    if dummy_path.exists():
        path = dummy_path
    elif real_path.exists():
        path = real_path
    else:
        findings.append({
            "id": "CHK-SSH-000",
            "title": "Archivo sshd_config no encontrado",
            "severity": "info",
            "evidence": "No se encontró dummy/sshd_config ni /etc/ssh/sshd_config",
            "remediation": "Crea un archivo dummy o verifica la instalación del servicio SSH.",
            "timestamp": datetime.datetime.now().isoformat()
        })
        return findings

    content = path.read_text(encoding="utf-8", errors="ignore").splitlines()

    # --- Agrupar parámetros y líneas (tolerante a espacios y tabulaciones) ---
    param_lines = {}

    for i, line in enumerate(content, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        parts = stripped.split(None, 1)
        if len(parts) == 2:
            key, value = parts[0].strip(), parts[1].strip()
            param_lines.setdefault(key, []).append((i, value))

    # === Reglas de análisis ===

    # 1️⃣ PermitRootLogin habilitado
    if "PermitRootLogin" in param_lines:
        lines = [str(i) for i, v in param_lines["PermitRootLogin"] if v.lower() == "yes"]
        if lines:
            findings.append({
                "id": "CHK-SSH-001",
                "title": "PermitRootLogin habilitado",
                "severity": "alta",
                "evidence": f"Encontrado 'PermitRootLogin yes' en líneas {', '.join(lines)}",
                "remediation": "Cambiar a 'PermitRootLogin no'.",
                "timestamp": datetime.datetime.now().isoformat()
            })

    # 2️⃣ PasswordAuthentication habilitado
    if "PasswordAuthentication" in param_lines:
        lines = [str(i) for i, v in param_lines["PasswordAuthentication"] if v.lower() == "yes"]
        if lines:
            findings.append({
                "id": "CHK-SSH-002",
                "title": "Autenticación por contraseña habilitada",
                "severity": "media",
                "evidence": f"Encontrado 'PasswordAuthentication yes' en líneas {', '.join(lines)}",
                "remediation": "Usar 'PasswordAuthentication no' para forzar claves públicas.",
                "timestamp": datetime.datetime.now().isoformat()
            })

    # 3️⃣ ChallengeResponseAuthentication habilitado
    if "ChallengeResponseAuthentication" in param_lines:
        lines = [str(i) for i, v in param_lines["ChallengeResponseAuthentication"] if v.lower() == "yes"]
        if lines:
            findings.append({
                "id": "CHK-SSH-003",
                "title": "ChallengeResponseAuthentication habilitado",
                "severity": "media",
                "evidence": f"Encontrado 'ChallengeResponseAuthentication yes' en líneas {', '.join(lines)}",
                "remediation": "Cambiar a 'ChallengeResponseAuthentication no'.",
                "timestamp": datetime.datetime.now().isoformat()
            })

    # 4️⃣ UsePAM habilitado
    if "UsePAM" in param_lines:
        lines = [str(i) for i, v in param_lines["UsePAM"] if v.lower() == "yes"]
        if lines:
            findings.append({
                "id": "CHK-SSH-004",
                "title": "PAM habilitado",
                "severity": "baja",
                "evidence": f"Encontrado 'UsePAM yes' en líneas {', '.join(lines)}",
                "remediation": "Deshabilitar 'UsePAM' si no es necesario.",
                "timestamp": datetime.datetime.now().isoformat()
            })

    # 5️⃣ Puerto por defecto 22
    if "Port" in param_lines:
        lines = [str(i) for i, v in param_lines["Port"] if v.strip() == "22"]
        if lines:
            findings.append({
                "id": "CHK-SSH-005",
                "title": "Uso del puerto por defecto (22)",
                "severity": "media",
                "evidence": f"Encontrado 'Port 22' en líneas {', '.join(lines)}",
                "remediation": "Cambiar el puerto a uno superior a 1024 (por ejemplo 2222).",
                "timestamp": datetime.datetime.now().isoformat()
            })

    # 6️⃣ Nivel de log bajo
    if "LogLevel" in param_lines:
        lines = [str(i) for i, v in param_lines["LogLevel"] if v.upper() in ("QUIET", "SILENT")]
        if lines:
            findings.append({
                "id": "CHK-SSH-006",
                "title": "Nivel de log bajo",
                "severity": "baja",
                "evidence": f"Encontrado 'LogLevel QUIET/SILENT' en líneas {', '.join(lines)}",
                "remediation": "Usar 'LogLevel INFO' o 'VERBOSE'.",
                "timestamp": datetime.datetime.now().isoformat()
            })

    # 7️⃣ Timeout ausente
    if "ClientAliveInterval" not in param_lines:
        findings.append({
            "id": "CHK-SSH-007",
            "title": "Timeout no configurado (ClientAliveInterval ausente)",
            "severity": "media",
            "evidence": "No se encontró la opción ClientAliveInterval en sshd_config.",
            "remediation": "Agregar 'ClientAliveInterval 300' y 'ClientAliveCountMax 2'.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    # 8️⃣ Parámetros duplicados
    duplicates = {k: [str(i) for i, _ in v] for k, v in param_lines.items() if len(v) > 1}
    if duplicates:
        details = "; ".join([f"{k}: líneas {', '.join(v)}" for k, v in duplicates.items()])
        findings.append({
            "id": "CHK-SSH-011",
            "title": "Parámetros duplicados detectados",
            "severity": "media",
            "evidence": details,
            "remediation": "Eliminar o unificar configuraciones repetidas para evitar conflictos.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    # 9️⃣ Parámetros críticos ausentes
    required_params = ["Protocol", "PermitRootLogin", "PasswordAuthentication", "ClientAliveInterval"]
    missing = [p for p in required_params if p not in param_lines]
    if missing:
        findings.append({
            "id": "CHK-SSH-012",
            "title": "Parámetros críticos ausentes",
            "severity": "media",
            "evidence": f"No se encontraron: {', '.join(missing)}",
            "remediation": "Definir explícitamente los parámetros ausentes en sshd_config.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    # 🔟 Parámetros desconocidos
    valid_params = [
        "Port", "AddressFamily", "ListenAddress", "Protocol", "HostKey",
        "LoginGraceTime", "PermitRootLogin", "StrictModes", "MaxAuthTries",
        "MaxSessions", "PubkeyAuthentication", "AuthorizedKeysFile", "PasswordAuthentication",
        "ChallengeResponseAuthentication", "UsePAM", "AllowTcpForwarding", "X11Forwarding",
        "ClientAliveInterval", "ClientAliveCountMax", "Banner", "LogLevel"
    ]
    invalid_lines = []
    for i, line in enumerate(content, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key = stripped.split()[0]
        if key not in valid_params and not key.isupper():
            invalid_lines.append(f"Línea {i}: {stripped}")

    if invalid_lines:
        findings.append({
            "id": "CHK-SSH-013",
            "title": "Parámetros desconocidos o líneas inválidas",
            "severity": "baja",
            "evidence": "; ".join(invalid_lines),
            "remediation": "Revisar las líneas no reconocidas o eliminar configuraciones inválidas.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    # 11️⃣ Configuración segura (si no se encontraron hallazgos)
    if not findings:
        findings.append({
            "id": "CHK-SSH-999",
            "title": "Configuración SSH segura",
            "severity": "baja",
            "evidence": f"No se encontraron configuraciones inseguras en {path}.",
            "remediation": "No se requiere acción.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    return findings
