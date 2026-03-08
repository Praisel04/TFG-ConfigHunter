# TFG-GoAudit




**23-11-2025:** Se ha conseguido crregir el fallo de la seleccion de modulos utilizando Typer.
Ahora podemos utilizar `python main.py scan` para ejecutar un analisis de todos los modulos definido o se puede usar `python main.py scan modulo` para elegir que modulo se analizara individualemnte.

Unico modulo  **SSH** por ahora solo utilizaremos este modulo , hasta dejarlo completo, seguro y funcional incluyendo la generación de documentos.

La documentacion de la criticidad de los servicios se ha sacado de **CIS Center For Internet Security** y **NIST SP 800-53**

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

**12-02-2026**
Se ha comenzado la definición para la implementación de Ollama en la generación de informes de análisis forense

**08-03-2026**

Se ha obtenido la primera version funcional completa de la herramienta.
ACTUALMENTE:
    - Herramienta realiza escaneo de los modulos ssh y ufw de maquinas ubuntu.
    - Se generan informes de reporte sobre los hallazgos encontrados y toda la informacion relativa a ellos.
    - Se genera el playbook de analisis forense completo, enriquecido con las técnicas de MITRE
    Ante cualquier duda sobre la costruccion del playbook revisar el archivo flujos_de_trabajo.md
Aun se deben validar de forma completa los indicadores FDIR y la checklist generica


**COSAS POR HACER**

**PRIORIDAD ALTA**
Comprobar indicadores FDIR del playbook de analisis forense
Terminar configuraciones de CLI y mejorar la apariencia
Comenzar documentacion de TFG.

**PRIORIDAD MEDIA**
COMPROBAR PERMISOS DE LA HERRAMIENTA, COMPROBAR LA CREACION DE LA CARPETA REPORTS COMO SUDO.



**PRIORIDAD BAJA**

Comenzar el flujo de Ollama con modelo IA para la generación de Informe de Análisis Forense incluyendo MITTRE ATT&CK Y CYBER KILL CHAIN (APLAZADO)

**OBJETIVOS DE FUTURO**
CREAR PLAYBOOK REPRODUCIBLE DE REMEDIACIÓN CON UN SCRIPT.





