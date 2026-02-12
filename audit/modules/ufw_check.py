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

    #Creacion de entorno y forzar idioma a ingles.
    

    # ============================================================
    # 1. CARGAR UFW STATUS (real o dummy)
    # ============================================================

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
            "explanation": "No se puede analizar el firewall si no es posible obtener su estado.",
            "cis_ref": None,
            "evidence": str(e),
            "remediation": "Crear dummy/ufw_status.txt o instalar UFW.",
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
            status = lower.replace("status:","").strip()

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
            "severity": "critica",
            "explanation": "Si UFW está desactivado, no se aplica ningún control de tráfico, dejando el sistema completamente expuesto.",
            "cis_ref": "CIS 4.1.2 | CCI-002314 | STIG ID UBTU-22-251015",
            "evidence": f"Status: {status}",
            "remediation": "ufw enable",
            "timestamp": timestamp
        })

    # UFW-102 — DEFAULT INPUT DENY
    if default_in != "deny":
        findings.append({
            "id": "UFW-102",
            "title": "La política de entrada no es DENY",
            "severity": "alta",
            "explanation": "La política entrante debe bloquear todo el tráfico no solicitado. Permitirlo abre servicios inesperados al exterior.",
            "cis_ref": "CIS 4.1.3 | NIST SP 800-53 REV 5",
            "evidence": f"default incoming = {default_in}",
            "remediation": "ufw default deny incoming",
            "timestamp": timestamp
        })

    # UFW-103 — DEFAULT OUTPUT ALLOW
    #if default_out != "allow":
    #    findings.append({
    #        "id": "UFW-103",
    #        "title": "Recomendación: La política de salida no es ALLOW",
    #        "severity": "baja",
    #        "explanation": "CIS recomienda permitir tráfico saliente por defecto salvo restricciones corporativas específicas.",
    #        "cis_ref": "CIS 4.1.2",
    #        "evidence": f"default outgoing = {default_out}",
    #        "remediation": "ufw default allow outgoing",
    #       "timestamp": timestamp
    #    })

    # UFW-104 — LOGGING
    #if logging == "off":
    #    findings.append({
    #        "id": "UFW-104",
    #        "title": "Logging de UFW desactivado",
    #        "severity": "baja",
    #        "explanation": "Sin logging no es posible detectar ni rastrear actividades maliciosas.",
    #        "cis_ref": "CIS 4.1.3",
    #        "evidence": "Logging: off",
    #        "remediation": "ufw logging on",
    #        "timestamp": timestamp
    #    })



    # ============================================================
    # 🟦 UFW-200 — SSH SECURITY
    # ============================================================

    for r in rules:
        rl = r.lower()
        port = extract_port(rl)
        if port != "22":
            continue

        if "anywhere" in rl or "0.0.0.0/0" in rl:
            findings.append({
                "id": "UFW-201-HARDENING",
                "title": "SSH expuesto públicamente (IPv4)",
                "severity": "alta",
                "explanation": "Permitir SSH desde cualquier origen facilita ataques de fuerza bruta. Se recomienda modificar este parámetro si no es estrictamente necesario.",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
                "evidence": r,
                "remediation": "ufw allow from <IP> to any port 22",
                "timestamp": timestamp
            })

        if "::/0" in rl or "anywhere (v6)" in rl:
            findings.append({
                "id": "UFW-201-HARDENING",
                "title": "SSH expuesto públicamente (IPv6)",
                "severity": "alta",
                "explanation": "Permitir SSH en IPv6 global expone el servicio a todo Internet. Se recomienda modificar este parámetro si no es estrictamente necesario.",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
                "evidence": r,
                "remediation": "Restringir acceso SSH en IPv6.",
                "timestamp": timestamp
            })

    # ============================================================
    # 🟥 UFW-300 — REGLAS AVANZADAS
    # ============================================================

    for r in rules:
        rl = r.lower()
        port = extract_port(rl)

        # UFW-301 — ALLOW sin LIMIT
        if "allow" in rl and "limit" not in rl:
            findings.append({
                "id": "UFW-301-HARDENING",
                "title": "Regla ALLOW sin LIMIT",
                "severity": "media",
                "explanation": "Las reglas ALLOW facilitan ataques de fuerza bruta mientras que LIMIT protege contra DoS y accesos repetidos. Se recomienda modificar este parametro si no es estrictamente necesario",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
                "evidence": r,
                "remediation": f"ufw limit {port}/tcp",
                "timestamp": timestamp
            })

        # UFW-302 — ANY/ANY
        if "allow" in rl and "anywhere" in rl:
            findings.append({
                "id": "UFW-302-HARDENING",
                "title": "Regla demasiado permisiva (ANY/ANY)",
                "severity": "alta",
                "explanation": "Permitir tráfico desde Anywhere viola las políticas de control de acceso para mantener segura la máquina. Se recomienda modificar este parámetro si no es estrictamente necesario.",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
                "evidence": r,
                "remediation": "Restringir la regla a IPs específicas.",
                "timestamp": timestamp
            })

        # UFW-303 — Exposición total
        if "0.0.0.0/0" in rl or "::/0" in rl:
            findings.append({
                "id": "UFW-303-HARDENING",
                "title": "Exposición total a Internet",
                "severity": "media",
                "explanation": "El rango 0.0.0.0/0 o ::/0 permite cualquier conexión de forma externa. Se recomienda modificar este parámetro si no es estrictamente necesario.",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
                "evidence": r,
                "remediation": "Restringir origen o eliminar regla.",
                "timestamp": timestamp
            })

        # UFW-304 — CIDR demasiado amplio
        cidr_match = re.search(r"/(\d{1,2})", rl)
        if cidr_match:
            c = int(cidr_match.group(1))
            if c < 24:
                findings.append({
                    "id": "UFW-304-HARDENING",
                    "title": f"CIDR demasiado amplio (/ {c})",
                    "severity": "media",
                    "explanation": "Máscaras amplias permiten acceso desde redes más amplias ampliando la superficie de ataque. Se recomienda modificar este parámetro si no es estrictamente necesario.",
                    "cis_ref": "Recomendación Adicional de ConfigHunter",
                    "evidence": r,
                    "remediation": "Usar /24 o IP específica.",
                    "timestamp": timestamp
                })

        # UFW-305 — Regla sin puerto específico
        if port is None:
            findings.append({
                "id": "UFW-305-HARDENING",
                "title": "Regla sin puerto definido",
                "severity": "media",
                "explanation": "Las reglas sin puerto definido son ambiguas y pueden producir accesos no deseados. Se recomienda modificar este parámetro si no es estrictamente necesario.",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
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
            "id": "UFW-401-HARDENING",
            "title": "Reglas duplicadas detectadas",
            "severity": "media",
            "explanation": "Las reglas duplicadas pueden generar comportamientos inconsistentes.",
            "cis_ref": "Recomendación Adicional de ConfigHunter",
            "evidence": "; ".join(dups),
            "remediation": "ufw delete <número>",
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
                "id": "UFW-402-HARDENING",
                "title": f"Conflicto allow/deny en el puerto {port}",
                "severity": "alta",
                "explanation": "Tener ALLOW y DENY simultáneos en un puerto genera resultados impredecibles.",
                "cis_ref": "Recomendación Adicional de ConfigHunter",
                "evidence": f"Acciones detectadas: {actions}",
                "remediation": "Unificar reglas: usa ALLOW o DENY, no ambos.",
                "timestamp": timestamp
            })
    
    # UFW-403 — Falta de protocolo
    missing_proto = []
    for r in rules:
        rl = r.lower()
        port = extract_port(rl)
        if port and "/" not in rl:
            missing_proto.append(r)

    if missing_proto:
        findings.append({
            "id": "UFW-403-HARDENING",
            "title": "Reglas sin especificar protocolo (tcp/udp)",
            "severity": "baja",
            "explanation": "No definir el protocolo impide aplicar políticas precisas.",
            "cis_ref": "Recomendación Adicional de ConfigHunter",
            "evidence": "; ".join(missing_proto),
            "remediation": "ufw allow | limit <port> / tcp|udp",
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
            "explanation": "No se detectaron configuraciones inseguras.",
            "cis_ref": None,
            "evidence": "No se encontraron problemas.",
            "remediation": "No se requiere acción.",
            "timestamp": timestamp
        })

    return findings
