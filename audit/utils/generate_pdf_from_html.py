import pdfkit
from pathlib import Path

def generate_pdf_from_html(module_name="ALL"):
    # Genera el PDF correspondiente al módulo indicado

    base_path = Path(__file__).resolve().parent.parent
    reports_path = base_path / "reports"

    # HTML de entrada según módulo
    if module_name == "ALL":
        html_filename = "report.html"
        pdf_filename = "Security_Audit_Report.pdf"
    else:
        html_filename = f"{module_name}_Report.html"
        pdf_filename = f"{module_name}_Report.pdf"

    html_path = reports_path / html_filename
    pdf_path = reports_path / pdf_filename

    if not html_path.exists():
        print(f"❌ No se encontró {html_path}. Ejecuta primero generate_html_report().")
        return

    try:
        options = {
            "page-size": "A4",
            "encoding": "UTF-8",
            "margin-top": "10mm",
            "margin-bottom": "10mm",
            "margin-left": "10mm",
            "margin-right": "10mm",
            "enable-local-file-access": None
        }

        pdfkit.from_file(str(html_path), str(pdf_path), options=options)
        print(f"✔ PDF generado correctamente: {pdf_path}")

    except OSError:
        print("❌ Error: wkhtmltopdf no está instalado o no se encuentra en el PATH.")
        print("➡ Instálalo según tu sistema operativo:")
        print("   - Windows: https://wkhtmltopdf.org/downloads.html")
        print("   - Linux: sudo apt install wkhtmltopdf")
        print("   - macOS: brew install wkhtmltopdf")


if __name__ == "__main__":
    generate_pdf_from_html()
