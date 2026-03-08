import json
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from utils.playbook_engine import enrich_hallazgo
from utils.generate_pdf_from_html import generate_pdf_from_html


# ============================================================================
# RUTAS DEL PROYECTO
# ============================================================================
BASE_DIR = Path(__file__).resolve().parent.parent
REPORTS_DIR = BASE_DIR / "reports"
TEMPLATES_DIR = BASE_DIR / "templates"


REPORTS_DIR.mkdir(exist_ok=True)


# ============================================================================
# HALLAZGOS RELEVANTES PARA PLAYBOOK
# ============================================================================
# Nota: Esto debe coincidir con los IDs normalizados en playbook_engine.py

PLAYBOOK_TARGETS = {
    "Access_sshd_config",
    "SSH_PrivateHostKey_Permissions",
    "DisableForwarding",
    "GSSAPIAuthentication",
    "KexAlgorithms",
    "MACs",
    "WeakCiphers",
    "LoginGraceTime",
    "LogLevel",
    "UsePAM",
    "PermitRootLogin",
    "PermitEmptyPasswords",
    "MaxAuthTries",
    "MaxSessions",
    "MaxStartups",
    "ClientAliveConfig"
}


# ============================================================================
# DETECCIÓN Y NORMALIZACIÓN DE HALLAZGOS PARA PLAYBOOK
# ============================================================================
def normalize_title(title: str):
    """
    Ajusta los títulos reales del reporte a los IDs internos del Playbook.
    """

    # Weak Ciphers (5.1.6)
    if "Ciphers inseguros" in title:
        return "WeakCiphers"

    # KexAlgorithms (5.1.12)
    if "KexAlgorithms inseguros" in title:
        return "KexAlgorithms"

    # MACs (5.1.15)
    if "MACs inseguras" in title or "Mac insegura" in title:
        return "MACs"

    # ClientAliveInterval / ClientAliveCountMax (5.1.7)
    if "ClientAlive" in title:
        return "ClientAliveConfig"

    # HostbasedAuthentication (5.1.10)
    if "HostbasedAuthentication" in title:
        return "HostbasedAuthentication"

    # IgnoreRhosts (5.1.11)
    if "IgnoreRhosts" in title:
        return "IgnoreRhosts"

    # PermitUserEnvironment (5.1.21)
    if "PermitUserEnvironment" in title:
        return "PermitUserEnvironment"

    # AllowTcpForwarding (5.1.8)
    if "AllowTcpForwarding" in title:
        return "AllowTcpForwarding"

    # PermitRootLogin (5.1.20)
    if "PermitRootLogin" in title:
        return "PermitRootLogin"

    # PermitEmptyPasswords (5.1.19)
    if "PermitEmptyPasswords" in title:
        return "PermitEmptyPasswords"

    # MaxAuthTries (5.1.16)
    if "MaxAuthTries" in title:
        return "MaxAuthTries"

    # MaxSessions (5.1.17)
    if "MaxSessions" in title:
        return "MaxSessions"

    # MaxStartups (5.1.18)
    if "MaxStartups" in title:
        return "MaxStartups"

    # UsePAM (5.1.22)
    if "UsePAM" in title:
        return "UsePAM"

    # LoginGraceTime (5.1.13)
    if "LoginGraceTime" in title:
        return "LoginGraceTime"

    # LogLevel (5.1.14)
    if "LogLevel" in title:
        return "LogLevel"

    # GSSAPIAuthentication (5.1.9)
    if "GSSAPIAuthentication" in title:
        return "GSSAPIAuthentication"

    # AllowUsers / AllowGroups (5.1.4)
    if "AllowUsers" in title or "AllowGroups" in title:
        return "AllowUsersGroups"

    # Banner (5.1.5)
    if "Banner" in title:
        return "Banner"

    return None

# ============================================================================
# GENERAR PLAYBOOK
# ============================================================================
def generate_playbook_report():
    """
    Genera playbook.html y playbook.pdf a partir de findings.json,
    renderizando base_playbook.html con includes.
    """

    findings_file = REPORTS_DIR / "findings.json"
    if not findings_file.exists():
        print("❌ No existe findings.json. Ejecuta primero un scan.")
        return

    # ------------------------------------------------------------------
    # 1) Cargar Findings
    # ------------------------------------------------------------------
    data = json.loads(findings_file.read_text(encoding="utf-8"))
    all_findings = []

    for module in data.get("modules", []):
        all_findings.extend(module.get("findings", []))

    # ------------------------------------------------------------------
    # 2) Filtrar y normalizar títulos
    # ------------------------------------------------------------------
    ready_for_playbook = {}

    for f in all_findings:
        normalized = normalize_title(f.get("title", ""))
        if normalized in PLAYBOOK_TARGETS:
            # Unificar ClientAliveInterval y CountMax en 1 solo hallazgo
            if normalized not in ready_for_playbook:
                ready_for_playbook[normalized] = f
                ready_for_playbook[normalized]["normalized"] = normalized
            else:
                # Añadir evidencia complementaria
                old_evidence = ready_for_playbook[normalized]["evidence"]
                new_evidence = f.get("evidence", "")
                ready_for_playbook[normalized]["evidence"] = f"{old_evidence}\n{new_evidence}"

    if not ready_for_playbook:
        print("⚠ No hay hallazgos relevantes para el Playbook.")
        return

    # ------------------------------------------------------------------
    # 3) Enriquecer hallazgos
    # ------------------------------------------------------------------
    enriched = []
    for key, fdata in ready_for_playbook.items():
        enriched.append(
            enrich_hallazgo({
                "title": key,
                "evidence": fdata.get("evidence", ""),
                "severity": fdata.get("severity", ""),
                "cis_ref": fdata.get("cis_ref"),
                "remediation": fdata.get("remediation"),
                "explanation": fdata.get("explanation"),
            })
        )

    # ------------------------------------------------------------------
    # 4) Preparar Jinja2
    # ------------------------------------------------------------------
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    template = env.get_template("playbooks/base_playbook.html")


    fecha_actual = datetime.now().strftime("%d/%m/%Y")

    html_output = template.render(
        hallazgos=enriched,
        fecha=fecha_actual
    )

    # ------------------------------------------------------------------
    # 5) Guardar playbook.html
    # ------------------------------------------------------------------
    output_html = REPORTS_DIR / "playbook.html"
    output_html.write_text(html_output, encoding="utf-8")
    print(f"✔ Playbook HTML generado en: {output_html}")

    # ------------------------------------------------------------------
    # 6) Convertir a PDF con el motor común
    # ------------------------------------------------------------------
    generate_pdf_from_html("playbook")
    print(f"✔ Playbook PDF generado correctamente en: {REPORTS_DIR / 'playbook.pdf'}")


# Ejecutable directo
if __name__ == "__main__":
    generate_playbook_report()
