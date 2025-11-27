import subprocess
import datetime
from pathlib import Path
import re


def extract_port(rl: str):
    """
    Extrae un puerto de una regla UFW.
    Detecta formatos como:
      22/tcp, 80, 443/udp, 3306 (v6), etc.
    """
    match = re.search(r"\b(\d{1,5})(?:/(tcp|udp))?\b", rl)
    if match:
        return match.group(1)
    return None


def run():
    findings = []
    timestamp = datetime.datetime.now().isoformat()

    # ============================================================
    # 1. CARGAR UFW STATUS (real o dummy)
    # ============================================================

    dummy_path = Path("dummy/ufw_status.txt")

    if dummy_path.exists():
        raw = dummy_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    else:
        try:
            output = subprocess.check_output(
                ["ufw", "status", "verbose"],
                stderr=subprocess.STDOUT
            ).decode("utf-8", errors="ignore")
            raw = output.splitlines()
        except Exception as e:
            findings.append({
                "id": "UFW-000",
                "title": "No se pudo obtener el estado de UFW",
                "severity": "info",
                "evidence": str(e),
                "remediation": "Crea dummy/ufw_status.txt o instala UFW.",
                "timestamp": timestamp
            })
            return findings

    # ============================================================
    # 2. PARSEO
    # ============================================================

    status = "inactive"
    default_in = None
    default_out = None
    logging = None
    rules = []

    parsing_rules = False

    for line in raw:
        stripped = line.strip()
        lower = stripped.lower()

        if lower.startswith("status:"):
            status = lower.replace("status:", "").strip()

        if "default:" in lower:
            if "incoming" in lower:
                default_in = "deny" if "deny" in lower else "allow"
            if "outgoing" in lower:
                default_out = "allow" if "allow" in lower else "deny"

        if "logging:" in lower:
            logging = lower.replace("logging:", "").strip()

        if "---" in stripped:
            parsing_rules = True
            continue

        if parsing_rules and ("allow" in lower or "deny" in lower):
            rules.append(stripped)

    # ============================================================
    # 🟩 UFW-100 — BASELINE
    # ============================================================

    # UFW-101 — UFW ACTIVO
    if status != "active":
        findings.append({
            "id": "UFW-101",
            "title": "Firewall UFW desactivado",
            "severity": "alta",
            "evidence": f"Estado: {status}",
            "remediation": "Ejecutar: ufw enable",
            "timestamp": timestamp
        })

    # UFW-102 — DEFAULT INPUT DENY
    if default_in != "deny":
        findings.append({
            "id": "UFW-102",
            "title": "La política de entrada no es DENY",
            "severity": "alta",
            "evidence": f"default incoming = {default_in}",
            "remediation": "Ejecutar: ufw default deny incoming",
            "timestamp": timestamp
        })

    # UFW-103 — DEFAULT OUTPUT ALLOW (recomendación)
    if default_out != "allow":
        findings.append({
            "id": "UFW-103",
            "title": "Recomendación: La política de salida no es ALLOW",
            "severity": "baja",
            "evidence": f"default outgoing = {default_out}",
            "remediation": "Ejecutar: ufw default allow outgoing",
            "timestamp": timestamp
        })

    # UFW-104 — LOGGING
    if logging == "off":
        findings.append({
            "id": "UFW-104",
            "title": "Logging de UFW desactivado",
            "severity": "baja",
            "evidence": "Logging: off",
            "remediation": "Ejecutar: ufw logging on",
            "timestamp": timestamp
        })

    # ============================================================
    # 🟦 UFW-200 — SSH SECURITY
    # ============================================================

    for r in rules:
        rl = r.lower()
        port = extract_port(rl)
        if port != "22":
            continue

        # IPv4 exposed
        if "anywhere" in rl or "0.0.0.0/0" in rl:
            findings.append({
                "id": "UFW-201",
                "title": "SSH expuesto públicamente (IPv4)",
                "severity": "alta",
                "evidence": r,
                "remediation": "Restringir SSH: ufw allow from <IP> to any port 22",
                "timestamp": timestamp
            })

        # IPv6 exposed
        if "::/0" in rl or "anywhere (v6)" in rl:
            findings.append({
                "id": "UFW-201",
                "title": "SSH expuesto públicamente (IPv6)",
                "severity": "alta",
                "evidence": r,
                "remediation": "Restringir acceso SSH en IPv6.",
                "timestamp": timestamp
            })

    # ============================================================
    # 🟥 UFW-300 — MISCONFIGURACIONES GRAVES
    # ============================================================

    for r in rules:
        rl = r.lower()
        port = extract_port(rl)

        # UFW-301 — ALLOW sin LIMIT
        if "allow" in rl and "limit" not in rl:
            findings.append({
                "id": "UFW-301",
                "title": "Regla ALLOW sin LIMIT (incumple STIG 600200)",
                "severity": "critica",
                "evidence": r,
                "remediation": f"Ejecutar: ufw limit {port}/tcp",
                "timestamp": timestamp
            })

        # UFW-302 — ANY/ANY
        if "allow" in rl and "anywhere" in rl:
            findings.append({
                "id": "UFW-302",
                "title": "Regla demasiado permisiva (ANY/ANY)",
                "severity": "critica",
                "evidence": r,
                "remediation": "Restringir la regla a IPs específicas.",
                "timestamp": timestamp
            })

        # UFW-303 — 0.0.0.0/0 o ::/0
        if "0.0.0.0/0" in rl or "::/0" in rl:
            findings.append({
                "id": "UFW-303",
                "title": "Exposición total (0.0.0.0/0 o ::/0)",
                "severity": "critica",
                "evidence": r,
                "remediation": "Restringir origen o eliminar regla.",
                "timestamp": timestamp
            })

        # UFW-304 — CIDR demasiado amplio
        cidr = re.search(r"/(\d{1,2})", rl)
        if cidr:
            c = int(cidr.group(1))
            if c < 24:
                findings.append({
                    "id": "UFW-304",
                    "title": f"CIDR demasiado amplio (/ {c})",
                    "severity": "alta",
                    "evidence": r,
                    "remediation": "Usar /24 o IP específica.",
                    "timestamp": timestamp
                })

        # UFW-305 — Regla sin puerto específico
        if port is None:
            findings.append({
                "id": "UFW-305",
                "title": "Regla sin puerto definido",
                "severity": "media",
                "evidence": r,
                "remediation": "Especificar el puerto en la regla.",
                "timestamp": timestamp
            })

    # ============================================================
    # 🟨 UFW-400 — INTEGRIDAD Y CONSISTENCIA
    # ============================================================

    # UFW-401 — Reglas duplicadas
    seen = set()
    dups = []
    for r in rules:
        key = r.lower().strip()
        if key in seen:
            dups.append(r)
        else:
            seen.add(key)

    if dups:
        findings.append({
            "id": "UFW-401",
            "title": "Reglas duplicadas detectadas",
            "severity": "media",
            "evidence": "; ".join(dups),
            "remediation": "Eliminar duplicados con: ufw delete <número>",
            "timestamp": timestamp
        })

    # UFW-402 — Conflicto allow/deny
    port_actions = {}
    for r in rules:
        rl = r.lower()
        port = extract_port(rl)
        if not port:
            continue

        action = "allow" if "allow" in rl else "deny"
        port_actions.setdefault(port, set()).add(action)

    for port, actions in port_actions.items():
        if len(actions) > 1:
            findings.append({
                "id": "UFW-402",
                "title": f"Conflicto allow/deny en el puerto {port}",
                "severity": "alta",
                "evidence": f"Acciones detectadas: {actions}",
                "remediation": "Unificar reglas: usa ALLOW o DENY, no ambos.",
                "timestamp": timestamp
            })

    # UFW-403 — Reglas mal formadas
    malformed = []
    for r in rules:
        rl = r.lower()
        port = extract_port(rl)

        if ("allow" not in rl and "deny" not in rl) or port is None:
            malformed.append(r)

    if malformed:
        findings.append({
            "id": "UFW-403",
            "title": "Reglas mal formadas o incompletas",
            "severity": "media",
            "evidence": "; ".join(malformed),
            "remediation": "Recrear la regla correctamente.",
            "timestamp": timestamp
        })

    # UFW-406 — Falta de protocolo (tcp/udp)
    missing_proto = []
    for r in rules:
        rl = r.lower()
        port = extract_port(rl)
        if port and "/" not in rl:
            missing_proto.append(r)

    if missing_proto:
        findings.append({
            "id": "UFW-406",
            "title": "Reglas sin especificar protocolo (tcp/udp)",
            "severity": "media",
            "evidence": "; ".join(missing_proto),
            "remediation": "Ejemplo: ufw allow 80/tcp",
            "timestamp": timestamp
        })

    # ============================================================
    # FIN
    # ============================================================

    if not findings:
        findings.append({
            "id": "UFW-999",
            "title": "Configuración UFW segura",
            "severity": "info",
            "evidence": "No se han encontrado problemas.",
            "remediation": "No se requiere acción.",
            "timestamp": timestamp
        })

    return findings
