# Auditoría Automatizada de Seguridad del Sistema -- GoAudit (Nombre provisional)

## 1. Descripción General

Este proyecto implementa una herramienta de auditoría automatizada para sistemas Linux, enfocada en detectar configuraciones inseguras, generar informes estructurados y documentar resultados de manera profesional. El estado actual de la aplicacion solo analiza la configuracion **SSH**  a través de un archivo **Dummy** que simula la configuración de ssh_config en un sistema Linux real.

Con el paso del tiempo se iran añadiendo módulos que analizaran todos los aspectos del sistema que sean configurables. 

Esta aplicación se basa en el uso de aplicaciones de escaneo como Lynis. 
**¿Qué incluye nuevo esta aplicación?**
La idea de esta aplicación es que sea completamente modular, permitiendo escanear de forma sencilla cualquier nodo de configuración ademas de generar documentaciones de forma rapida y clara.

Actualmente solo genera un informe con una tabla que muestra las configuraciones inseguras encontradas en ssh_config y muestra una tabla con el nombre, datos, criticidad, evidencia y resolución. Posteriormente, se agregaran memorias para replicar el fallo y playbooks para su ejecución y guias completas y detalladas para su resolución. 


>Realizado por:
> -Ivan Seco Martín

------------------------------------------------------------------------

## 2. Objetivos

* Analizar configuraciones críticas del sistema .

* Detectar y clasificar vulnerabilidades según su severidad.

* Generar informes automáticos en JSON, HTML y PDF.

* Automatizar el proceso completo desde la detección hasta la documentación.

------------------------------------------------------------------------

## 3. Arquitectura General del Proyecto

``` text
audit/
│
├── dummy/                  # Archivos simulados para pruebas
├── modules/                # Módulos de auditoría (SSH, validador, etc.)
│   ├── ssh_check.py
│   └── validator_check.py
├── reports/                # Resultados generados
│   ├── findings.json
│   ├── report.html
│   └── Security_Audit_Report.pdf
├── templates/              # Plantillas HTML Jinja2
│   ├── base.html
│   └── ...
├── utils/                  # Utilidades de generación
│   ├── generate_html_report.py
│   ├── generate_pdf_from_html.py
├── main.py                 # Punto de entrada
└── requirements.txt
```
------------------------------------------------------------------------

## 4. Funcionamiento Generico de la aplicación
1. Escaneo: `main.py` ejecuta los módulos de auditoría (como ssh_check).
**`python main.py scan`** o **`python main.py scan ssh`**   
2. Resultados: se consolidan en findings.json con las evidencias encontradas.
3. Documentación: se generan automáticamente los informes HTML y PDF mediante las funciones de utils.
------------------------------------------------------------------------

## 5. Módulo SSH (modules/ssh_check.py)

Evalúa sshd_config (dummy o real) buscando configuraciones inseguras:

* PermitRootLogin yes → severidad alta
* PasswordAuthentication yes → media
* Port 22 → media
* Parámetros duplicados o inválidos
* Ausencia de parámetros críticos
Cada hallazgo se devuelve en formato JSON, incluyendo evidencia y recomendación.

>_**La eleccion de los indicadores de criticidad se basan en lo expuesto en CIS Center For Internet Security y NIST SP 800-53**_

------------------------------------------------------------------------

## 6. Generacion de Informes (actual)
**1. generate_html_report.py:** Convierte los datos de **findings.json** en un HTML utilizando Jinja2.
**2, generate_pdf_from_html.py:** Transforma el HTML en un PDF utilizando las librerias de `pdfkit / wkhtmltopdf`

------------------------------------------------------------------------

## 7. Instalación de dependencias

* Typer –  CLI moderna y limpia
* Rich –   Formateo de consola
* Jinja2 – Motor de plantillas HTML
* PDFKit + wkhtmltopdf – Conversión de HTML a PDF

```bash
pip install -r requirements.txt
```
## 8. Proximas mejoras
* Nuevos módulos (firewall, usuarios, contraseñas). **Alta prioridad**
* Integrar estándares CIS Benchmark. **Alta Prioridad**
* Dashboard web interactivo. **Media Prioridad**
* Incorporación de IA / Heurística para priorización de riesgos. **Aún no pensada**

## 9. Conclusiones
Este sistema ofrece unas coluciones optimas para la revisión de configuraciones inseguras. Capaz de escalar de forma sencilla ante nuevas configuraciones o fallos nuevos detectados.