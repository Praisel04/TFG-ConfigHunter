import subprocess
import sys
from pathlib import Path


def generate_pdf_from_html(module_name="ALL"):
    """
    Convierte el HTML correcto a PDF según el módulo.

    Añadido soporte especial para:
      - playbook.html → playbook.pdf
    """

    base_path = Path(__file__).resolve().parent.parent
    reports_path = base_path / "reports"

    # =====================================================
    # TRATAMIENTO ESPECIAL PARA PLAYBOOK
    # =====================================================
    if module_name.lower() == "playbook":
        html_file = "playbook.html"
        pdf_file = "playbook.pdf"
    else:
        # ===============================================
        # Módulos estándar (SSH, ALL, UFW, etc.)
        # ===============================================
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
        

        result = subprocess.run(
            wk_options,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Si ocurre un error real
        if result.returncode != 0:
            print("❌ Error al generar el PDF:")
            print(result.stderr)
            sys.exit(1)

        print(f"✔ PDF generado correctamente: {pdf_path}")

    except Exception as e:
        print(f"❌ Error inesperado al generar el PDF: {e}")
        sys.exit(1)


if __name__ == "__main__":
    generate_pdf_from_html()