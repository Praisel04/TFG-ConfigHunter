from pathlib import Path
import json
import datetime
import re

def run():
    findings = []
    ssh_path = Path("dummy/sshd_config")
    if not ssh_path.exists():
        return []

    content = ssh_path.read_text(encoding="utf-8", errors="ignore").splitlines()

    # --- Detectar parámetros duplicados generales ---
    param_lines = {}
    for i, line in enumerate(content, start=1):
        if not line.strip() or line.strip().startswith("#"):
            continue
        key = line.split()[0]
        if key not in param_lines:
            param_lines[key] = []
        param_lines[key].append(i)

    duplicates = {k: v for k, v in param_lines.items() if len(v) > 1}

    if duplicates:
        evidence = "; ".join([f"{k}: líneas {', '.join(map(str, v))}" for k, v in duplicates.items()])
        findings.append({
            "id": "CHK-GEN-001",
            "title": "Parámetros duplicados globales",
            "severity": "media",
            "evidence": evidence,
            "remediation": "Eliminar o consolidar parámetros repetidos para evitar conflictos.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    # --- Detectar incoherencias de valores (conflictos) ---
    conflicts = []
    for key, lines in param_lines.items():
        values = []
        for i in lines:
            tokens = content[i - 1].split()
            if len(tokens) > 1:
                values.append(tokens[1])
        if len(set(values)) > 1:
            conflicts.append(f"{key}: {', '.join(values)} (líneas {', '.join(map(str, lines))})")

    if conflicts:
        findings.append({
            "id": "CHK-GEN-002",
            "title": "Parámetros con valores conflictivos",
            "severity": "alta",
            "evidence": "; ".join(conflicts),
            "remediation": "Mantener un único valor coherente para cada parámetro duplicado.",
            "timestamp": datetime.datetime.now().isoformat()
        })

    Path("reports").mkdir(exist_ok=True)
    with open("reports/validator_findings.json", "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=4, ensure_ascii=False)

    return findings
