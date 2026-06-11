from typing import Optional
from rich.console import Console
import typer

app = typer.Typer()
console = Console()

@app.command()
def scan(module: str = typer.Argument(None, help="Nombre del módulo a escanear (ssh, ufw, firewall...)")):
    # Ejecuta un escaneo de seguridad: individual o completo

    from datetime import datetime
    from pathlib import Path
    import importlib
    import json

    console.print("[bold cyan]=== AUDITORÍA AUTOMATIZADA ===[/bold cyan]\n")

    # Alias de módulos
    alias_map = {
        "ssh": "ssh",
        "ufw": "ufw",
        "firewall": "ufw"
    }

    if module:
        module = alias_map.get(module.lower(), module.lower())

    # Saber si es un escaneo individual
    is_single_scan = module is not None

    # Módulos disponibles
    modules_path = Path("modules")
    available_modules = [p.stem for p in modules_path.glob("*_check.py")]

    # Selección de módulos a ejecutar
    if module:
        if f"{module}_check" not in available_modules:
            console.print(f"[bold red]❌ Módulo '{module}' no encontrado.[/bold red]")
            console.print(f"[bold yellow]Módulos disponibles:[/bold yellow] {', '.join(available_modules)}")
            raise typer.Exit()
        modules_to_run = [f"{module}_check"]
    else:
        modules_to_run = available_modules

    console.print(f"[bold green]Ejecutando módulos:[/bold green] {', '.join(modules_to_run)}\n")

    all_findings = []
    module_blocks = []

    # Ejecutar módulos seleccionados
    for mod_name in modules_to_run:
        try:
            mod = importlib.import_module(f"modules.{mod_name}")
            console.print(f"[bold cyan]→ Ejecutando {mod_name}...[/bold cyan]")

            results = mod.run()

            module_blocks.append({
                "name": mod_name.replace("_check", "").upper(),
                "description": f"Resultados del análisis del módulo {mod_name}.",
                "findings": results
            })

            all_findings.extend(results)
            console.print(f"[green]✔ {len(results)} hallazgos obtenidos de {mod_name}.[/green]\n")

        except Exception as e:
            console.print(f"[bold red]Error ejecutando {mod_name}: {e}[/bold red]")

    # Resumen general
    summary = {"critica": 0, "alta": 0, "media": 0, "baja": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "").lower()
        if sev in summary:
            summary[sev] += 1
    summary["total"] = sum(summary.values())

    conclusion_text = (
        "Informe completo de todos los módulos."
        if not is_single_scan
        else f"Informe específico del módulo {module.upper()}."
    )

    unified_report = {
        "generated_on": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "system_name": "Localhost",
        "summary": summary,
        "modules": module_blocks,
        "conclusion": {
            "summary": conclusion_text,
            "recommendations": [
                "Revisar las configuraciones detectadas.",
                "Aplicar buenas prácticas de seguridad según los hallazgos."
            ]
        }
    }

    # Guardar JSON
    reports_path = Path("reports")
    reports_path.mkdir(exist_ok=True)
    json_path = reports_path / "findings.json"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(unified_report, f, indent=4, ensure_ascii=False)

    console.print(f"[bold green]✔ Informe JSON guardado en {json_path}[/bold green]\n")

    # Generar HTML
    try:
        from utils.generate_html_report import generate_html_report
        console.print("[cyan]→ Generando informe HTML...[/cyan]")

        html_module_name = "ALL" if not is_single_scan else module.upper()
        generate_html_report(html_module_name)

    except Exception as e:
        console.print(f"[red]Error generando HTML: {e}[/red]")

    # Generar PDF
    try:
        from utils.generate_pdf_from_html import generate_pdf_from_html
        pdf_module_name = "ALL" if not is_single_scan else module.upper()

        console.print("[cyan]→ Generando informe PDF...[/cyan]")

        generate_pdf_from_html(pdf_module_name)

        

    except Exception as e:
        console.print(f"[red]Error generando PDF: {e}[/red]")

    console.print(f"[bold yellow]Resumen:[/bold yellow] {summary}")
    console.print("[bold cyan]=== ESCANEO COMPLETADO ===[/bold cyan]\n")

    
    #  NUEVA FUNCIÓN: PREGUNTAR SI SE QUIERE GENERAR PLAYBOOKS
    

    answer = input("¿Desea generar el Playbook forense y de Threat Hunting? (Y/N): ").strip().lower()

    if answer == "y":
        console.print("\n[cyan]→ Generando Playbook forense...\n[/cyan]")
        try:
            from utils.generate_playbook_report import generate_playbook_report
            generate_playbook_report()
            console.print("[green]✔ Playbook generado correctamente![/green]\n")
            console.print("[bold yellow]Gracias por usar Config Hunter![/bold yellow]")
        except Exception as e:
            console.print(f"[red]Error generando Playbook: {e}[/red]")
    else:
        console.print("[bold yellow]Playbook no generado. Gracias por usar ConfigHunter![/bold yellow]")



if __name__ == "__main__":
    app()
