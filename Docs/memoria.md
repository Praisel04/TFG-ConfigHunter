


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

**24-11-2025**
Automatizacion de la generacion de informes

**26-11-2025**
Creacion de modulo de UFW y cambio en el formato de las reglas.

**27-11-2025**
Modificacion de las reglas del modulo SSH_CHECK. Completamente guiadas en CIS 5.x.x. Cambios en la documentacion ahora en texto y no en tabla. Mejora visual del PDF.
Nuevas decisiones. Informe general que incluya informacion de los hallazgos, remediacion detallada y playbooks completos con superficies de ataque, guias de explotacion, MITTRE ATTACK...

Se ha configurado un motor de reglas avanzados para la explicacion detallada de la remediacion de los hallazgos. Se ha cambiado la estetica del PDF a una mas profesional y avanzada con colores adecuados.


**07-02-2026**
Se ha migrado con exito la herramienta a una máquina virtual Ubuntu 22.04
Se ha comprobado el funcionamiento de la herramienta dentro de la MV.
Se han corregido fallos en algunas rutas y en algunos puntos.
Se ha modificado la plantilla especifica de ssh para la explicacion del reinicio del servicio sshd.
Se han comprobado todos los puntos contemplados en la guia CIS.
Añadidos los punto 5.12 y 5.15 de CIS en ssh_check.

**08-02-2026**
Eliminado el punto UFW-103 Y UFW-104, ya que son de nivel 2.
Comprobadas el primer bloque de reglas UFW.

**09-02-2026**
Se han modificado diferentes puntos y se han dejado referenciados como recomendaciones de la herramienta ya que no aparecen en el CIS.
Comprobado el modo scan-all de la herramienta y corregidos algunos comandos sudo sshd grep.




**COSAS POR HACER**

**PRIORIDAD ALTA**
COMPROBAR PERMISOS DE LA HERRAMIENTA, COMPROBAR LA CREACION DE LA CARPETA REPORTS COMO SUDO.

**PRIORIDAD MEDIA**
1. Definir los playbooks
2. Definir las tecnicas MITTRE y Kill Chain.
3. Terminar de construir el playbooks de información

**PRIORIDAD BAJA**
1. Revisar la generación del PDF. Corregir donde sale la parte de remediaciones avanzadas. Eliminar el apartado de playbook del PDF

**OBJETIVOS DE FUTURO**
CREAR PLAYBOOK REPRODUCIBLE DE REMEDIACIÓN CON UN SCRIPT.





