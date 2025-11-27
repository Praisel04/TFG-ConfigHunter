from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import json

def generate_html_report(module_name="ALL"):
    # Genera el informe HTML del módulo indicado

    base_path = Path(__file__).resolve().parent.parent
    templates_path = base_path / "templates"
    reports_path = base_path / "reports"
    findings_path = reports_path / "findings.json"

    # Nombre del archivo HTML final
    if module_name == "ALL":
        output_filename = "report.html"
    else:
        output_filename = f"{module_name}_Report.html"

    output_path = reports_path / output_filename

    if not findings_path.exists():
        print("❌ No se encontró reports/findings.json. Ejecuta primero un escaneo.")
        return

    # Cargar datos del JSON
    with open(findings_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Ordenar hallazgos por severidad
    severity_order = {
        "critica": 1,
        "crítica": 1,
        "alta": 2,
        "media": 3,
        "baja": 4,
        "info": 5
    }

    for module in data.get("modules", []):
        module["findings"].sort(
            key=lambda f: severity_order.get(f.get("severity", "").lower(), 99)
        )

    # Configurar Jinja2
    env = Environment(
        loader=FileSystemLoader(str(templates_path)),
        autoescape=select_autoescape(["html", "xml"])
    )

    template = env.get_template("base.html")

    rendered_html = template.render(
        generated_on=data.get("generated_on", ""),
        system_name=data.get("system_name", "No especificado"),
        summary=data.get("summary", {}),
        modules=data.get("modules", []),
        conclusion=data.get("conclusion", {})
    )

    # Guardar HTML
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    print(f"✔ Informe HTML generado correctamente: {output_path}")


if __name__ == "__main__":
    generate_html_report()
