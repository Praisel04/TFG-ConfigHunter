import subprocess
import sys
from pathlib import Path

def generate_pdf_from_html(module_name="ALL"):
    """
    Convierte el HTML correcto a PDF según el módulo.
    Gestiona correctamente:
      - report.html (informe completo)
      - SSH_Report.html
      - UFW_Report.html
      - VALIDATOR_Report.html
    """

    base_path = Path(__file__).resolve().parent.parent
    reports_path = base_path / "reports"

    # ===============================
    # Selección correcta del archivo
    # ===============================
    if module_name == "ALL":
        html_file = "report.html"
        pdf_file = "report.pdf"
    else:
        html_file = f"{module_name}_Report.html"
        pdf_file = f"{module_name}_Report.pdf"

    html_path = reports_path / html_file
    pdf_path = reports_path / pdf_file

    if not html_path.exists():
        print(f"❌ ERROR: No existe el archivo HTML: {html_path}")
        return

    # ===============================
    # Opciones PDF profesionales
    # ===============================
    wk_options = [
        "wkhtmltopdf",

        "--margin-top", "20mm",
        "--margin-bottom", "18mm",
        "--margin-left", "15mm",
        "--margin-right", "15mm",

        "--header-spacing", "5",
        "--header-line",
        "--header-left", "Auditoría de Seguridad",
        "--header-font-size", "10",
        "--header-font-name", "Arial",
        "--header-right", "[date]  |  Página [page] de [toPage]",

        "--footer-line",
        "--footer-spacing", "4",
        "--footer-font-size", "9",
        "--footer-left", "Informe generado automáticamente",
        "--footer-right", "Clasificación: CONFIDENCIAL",

        "--dpi", "150",
        "--disable-smart-shrinking",

        str(html_path),
        str(pdf_path)
    ]

    try:
        print("🧪 Generando PDF… (puede tardar unos segundos)")
        subprocess.run(wk_options, check=True)
        print(f"✔ PDF generado correctamente: {pdf_path}")

    except subprocess.CalledProcessError as e:
        print(f"❌ Error al generar el PDF: {e}")
        sys.exit(1)


if __name__ == "__main__":
    generate_pdf_from_html()
