from pathlib import Path
import json
from collections import Counter

def generate_global_report():
    reports_path = Path("reports")
    all_findings = []

    # --- Reunir todos los informes individuales ---
    for report in reports_path.glob("*_findings.json"):
        try:
            data = json.loads(report.read_text(encoding="utf-8"))
            origin = report.stem.replace("_findings", "")
            for item in data:
                item["origin"] = origin
                all_findings.append(item)
        except Exception as e:
            print(f"Error leyendo {report}: {e}")

    # --- Deduplicar (id + evidencia) ---
    unique_findings = []
    seen = set()
    for f in all_findings:
        key = (f.get("id"), f.get("evidence"))
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    # --- Contar severidades ---
    severities = [f.get("severity", "desconocida") for f in unique_findings]
    counts = Counter(severities)
    summary = {
        "alta": counts.get("alta", 0),
        "media": counts.get("media", 0),
        "baja": counts.get("baja", 0),
        "info": counts.get("info", 0),
        "total": len(unique_findings)
    }

    # --- Construir estructura final ---
    structured_output = {
        "summary": summary,
        "findings": unique_findings
    }

    # --- Guardar archivo final ---
    output_path = reports_path / "findings.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(structured_output, f, indent=4, ensure_ascii=False)

    print(f"✔ Informe global estructurado generado: {output_path}")
    print(f"→ Resumen: {summary}")

if __name__ == "__main__":
    generate_global_report()
