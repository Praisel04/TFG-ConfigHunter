


**23-11-2025:** Se ha conseguido crregir el fallo de la seleccion de modulos utilizando Typer.
Ahora podemos utilizar `python main.py scan` para ejecutar un analisis de todos los modulos definido o se puede usar `python main.py scan modulo` para elegir que modulo se analizara individualemnte.

Unico modulo  **SSH** por ahora solo utilizaremos este modulo , hasta dejarlo completo, seguro y funcional incluyendo la generación de documentos.

La documentacion de la criticidad de los servicios se ha sacado de **CIS Center For Internet Security** y **NIST SP 800-53**

| Chequeo implementado                  | Fuente / Justificación                         | Severidad |
| ------------------------------------- | ---------------------------------------------- | --------- |
| `PermitRootLogin yes`                 | CIS 5.2.9 / NIST AC-3                          | Alta      |
| `PasswordAuthentication yes`          | CIS 5.2.9 / NIST IA-2                          | Media     |
| `ChallengeResponseAuthentication yes` | CIS 5.2.6 / NIST IA-5                          | Media     |
| `UsePAM yes`                          | RedHat Hardening / CIS 5.2.x (evaluar entorno) | Baja      |
| `Port 22`                             | CIS 5.2.13 / NIST SC-7                         | Media     |
| `LogLevel QUIET`                      | CIS 5.2.13 / NIST AU-12                        | Baja      |
| `ClientAliveInterval` ausente         | CIS 5.2.14 / NIST SC-10                        | Media     |
| `AllowTcpForwarding yes`              | CIS 5.2.11 / NIST SC-7                         | Media     |
| `X11Forwarding yes`                   | CIS 5.2.12 / NIST SC-7                         | Baja      |
| `Protocol 1`                          | CIS 5.2.10 / NIST SC-13                        | Alta      |


Tras el escaneo se genera un JSON (findings) que contiene todo y una estructura para la generacion de HTML. Este HTML con jinja2 es la combinacion de varias plantillas predefenidas. Despues utilizamos pdfkit para convertirlo en un PDF que sera la doc final

**FLUJO DE EJECUCIÓN**

scan --> JSON --> `python -m utils.generate_html_report` --> HTML --> `python -m utils.generate_pdf_from_html` --> PDF