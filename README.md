# ConfigHunter

**ConfigHunter** es una herramienta modular de auditoría automatizada de configuraciones de seguridad en sistemas Linux. Su objetivo es detectar configuraciones inseguras en servicios críticos, generar hallazgos estructurados con evidencias y remediaciones, producir informes técnicos en distintos formatos y contextualizar determinados hallazgos mediante modelos defensivos como **MITRE ATT&CK** y **Cyber Kill Chain**.

Este proyecto ha sido desarrollado como parte de un **Trabajo Fin de Grado en Ingeniería Informática**.

---

## Índice

* [Descripción general](#descripción-general)
* [Características principales](#características-principales)
* [Arquitectura del proyecto](#arquitectura-del-proyecto)
* [Módulos implementados](#módulos-implementados)
* [Requisitos](#requisitos)
* [Instalación](#instalación)
* [Uso](#uso)
* [Salidas generadas](#salidas-generadas)
* [Playbooks de correlación defensiva](#playbooks-de-correlación-defensiva)
* [Validación experimental](#validación-experimental)
* [Resultados destacados](#resultados-destacados)
* [Limitaciones actuales](#limitaciones-actuales)
* [Líneas futuras](#líneas-futuras)
* [Advertencia de uso](#advertencia-de-uso)
* [Autor](#autor)
* [Licencia](#licencia)

---

## Descripción general

La seguridad de un sistema Linux no depende únicamente de que el software esté actualizado, sino también de que sus servicios, permisos, accesos y reglas de red estén configurados correctamente. Una configuración insegura puede facilitar accesos no autorizados, exposición de servicios, ataques de fuerza bruta, uso indebido de túneles o pérdida de trazabilidad durante una investigación posterior.

ConfigHunter nace para apoyar este proceso mediante una herramienta ligera, modular y extensible que permite auditar configuraciones concretas del sistema, comenzando por dos componentes especialmente relevantes:

* **OpenSSH**, como servicio crítico de administración remota.
* **UFW**, como mecanismo básico de filtrado de tráfico en sistemas Linux.

La herramienta genera hallazgos estructurados, clasificados por severidad, acompañados de evidencias directas y recomendaciones de remediación. Además, incorpora una capa de contextualización defensiva mediante playbooks, relacionando determinados hallazgos con posibles técnicas de ataque, fases de intrusión e indicadores útiles para análisis defensivo.

---

## Características principales

| Característica          | Descripción                                                              |
| ----------------------- | ------------------------------------------------------------------------ |
| Auditoría automatizada  | Revisión automática de configuraciones de seguridad en Linux.            |
| Arquitectura modular    | Separación por módulos independientes de análisis.                       |
| Módulo SSH              | Análisis de parámetros relevantes de OpenSSH.                            |
| Módulo UFW              | Análisis de estado, políticas y reglas del firewall UFW.                 |
| Hallazgos estructurados | Cada hallazgo incluye severidad, evidencia, referencia y remediación.    |
| Informes automáticos    | Generación de resultados en JSON, HTML y PDF.                            |
| Playbooks defensivos    | Contextualización de hallazgos mediante MITRE ATT&CK y Cyber Kill Chain. |
| Menú interactivo        | Ejecución guiada desde terminal.                                         |
| Enfoque extensible      | Preparado para incorporar nuevos módulos en futuras versiones.           |

---

## Arquitectura del proyecto

La estructura actual del repositorio es la siguiente:

```text
CONFIGHUNTER/
├── audit/
│   ├── modules/
│   │   ├── __init__.py
│   │   ├── ssh_check.py
│   │   └── ufw_check.py
│   ├── templates/
│   │   ├── playbooks/
│   │   ├── base.html
│   │   ├── conclusion.html
│   │   ├── cover.html
│   │   ├── details.html
│   │   ├── finding_block.html
│   │   ├── footer.html
│   │   ├── header.html
│   │   ├── module_section.html
│   │   ├── playbooks.html
│   │   ├── summary.html
│   │   └── toc.html
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── generate_global_report.py
│   │   ├── generate_html_report.py
│   │   ├── generate_pdf_from_html.py
│   │   ├── generate_playbook_report.py
│   │   └── playbook_engine.py
│   ├── confighunter
│   ├── main.py
│   └── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

### Descripción de carpetas principales

| Ruta                         | Función                                                        |
| ---------------------------- | -------------------------------------------------------------- |
| `audit/modules/`             | Contiene los módulos de análisis de seguridad.                 |
| `audit/templates/`           | Contiene las plantillas HTML utilizadas para generar informes. |
| `audit/templates/playbooks/` | Contiene plantillas específicas para los playbooks defensivos. |
| `audit/utils/`               | Contiene utilidades para generar informes, PDF y playbooks.    |
| `audit/main.py`              | Punto principal de ejecución de la herramienta.                |
| `audit/confighunter`         | Lanzador de la herramienta desde terminal.                     |
| `audit/requirements.txt`     | Dependencias necesarias para ejecutar ConfigHunter.            |

---

## Módulos implementados

### Módulo SSH

El módulo SSH analiza configuraciones relevantes del servicio **OpenSSH**. Entre los controles implementados se incluyen:

| Control                      | Riesgo asociado                                            |
| ---------------------------- | ---------------------------------------------------------- |
| `PermitRootLogin`            | Acceso directo del usuario root mediante SSH.              |
| `PermitEmptyPasswords`       | Posibilidad de autenticación con contraseñas vacías.       |
| `AllowTcpForwarding`         | Uso indebido de túneles SSH.                               |
| `HostbasedAuthentication`    | Autenticación basada en host potencialmente insegura.      |
| `IgnoreRhosts`               | Uso de mecanismos heredados de confianza entre hosts.      |
| `PermitUserEnvironment`      | Manipulación del entorno de usuario.                       |
| `UsePAM`                     | Control de autenticación mediante PAM.                     |
| `GSSAPIAuthentication`       | Superficie adicional de autenticación.                     |
| `MaxAuthTries`               | Número excesivo de intentos de autenticación.              |
| `MaxSessions`                | Número elevado de sesiones simultáneas.                    |
| `MaxStartups`                | Configuración demasiado permisiva de conexiones iniciales. |
| `ClientAliveInterval`        | Tiempo excesivo para detectar sesiones inactivas.          |
| `ClientAliveCountMax`        | Número elevado de comprobaciones de sesión.                |
| `Ciphers`                    | Uso de cifrados débiles.                                   |
| `KexAlgorithms`              | Uso de algoritmos de intercambio de claves inseguros.      |
| `MACs`                       | Uso de algoritmos MAC débiles.                             |
| `Banner`                     | Ausencia de banner legal o informativo.                    |
| `AllowUsers` / `AllowGroups` | Ausencia de restricciones explícitas de acceso.            |

---

### Módulo UFW

El módulo UFW analiza el estado del firewall y sus reglas principales.

| Control                         | Riesgo asociado                                            |
| ------------------------------- | ---------------------------------------------------------- |
| Estado de UFW                   | Firewall desactivado o no operativo.                       |
| Política por defecto de entrada | Entrada permitida por defecto.                             |
| Logging                         | Falta de registro de eventos del firewall.                 |
| Reglas `ALLOW` sin `LIMIT`      | Mayor exposición a fuerza bruta o abuso de servicios.      |
| Reglas `ANY/ANY`                | Acceso permitido desde cualquier origen.                   |
| Puertos expuestos               | Servicios accesibles en IPv4 o IPv6.                       |
| Reglas duplicadas               | Posible complejidad o inconsistencias en la configuración. |
| Conflictos `ALLOW/DENY`         | Reglas contradictorias sobre un mismo puerto.              |

---

## Requisitos

ConfigHunter está pensado para ejecutarse en sistemas Linux.

La validación principal del proyecto se realizó en:

| Componente           | Versión / herramienta |
| -------------------- | --------------------- |
| Sistema operativo    | Ubuntu 22.04.5 LTS    |
| Lenguaje             | Python 3              |
| Servicios analizados | OpenSSH Server y UFW  |
| Conversión PDF       | wkhtmltopdf           |
| Comparativa externa  | Lynis y OpenSCAP      |

Dependencias principales de Python:

* `typer`
* `rich`
* `jinja2`
* `pdfkit`

---

## Instalación

### 1. Clonar el repositorio

```bash
git clone https://github.com/TU_USUARIO/ConfigHunter.git
cd ConfigHunter/audit
```

> Sustituye `TU_USUARIO` por el nombre real de usuario o la organización donde esté publicado el repositorio.

### 2. Instalar dependencias de Python

```bash
pip install -r requirements.txt
```

### 3. Instalar wkhtmltopdf

En distribuciones basadas en Debian/Ubuntu:

```bash
sudo apt update
sudo apt install wkhtmltopdf
```

### 4. Dar permisos de ejecución al lanzador

```bash
chmod +x confighunter
```

---

## Uso

ConfigHunter debe ejecutarse con privilegios de administrador, ya que necesita consultar configuraciones del sistema:

```bash
sudo ./confighunter
```

Al ejecutarse, muestra un menú interactivo:

```text
1) Escaneo completo
2) Escaneo SSH
3) Escaneo Firewall (UFW)
4) Salir
```

### Opciones disponibles

| Opción                 | Descripción                                   |
| ---------------------- | --------------------------------------------- |
| Escaneo completo       | Ejecuta todos los módulos disponibles.        |
| Escaneo SSH            | Ejecuta únicamente el módulo de análisis SSH. |
| Escaneo Firewall (UFW) | Ejecuta únicamente el módulo de análisis UFW. |
| Salir                  | Finaliza la ejecución de la herramienta.      |

---

## Flujo de ejecución

El flujo lógico de ConfigHunter puede resumirse de la siguiente manera:

```text
Ejecución con sudo
        │
        ▼
Menú interactivo
        │
        ▼
Selección de módulo o escaneo completo
        │
        ▼
Ejecución de módulos SSH/UFW
        │
        ▼
Generación de hallazgos estructurados
        │
        ▼
Almacenamiento en findings.json
        │
        ▼
Generación de informe HTML
        │
        ▼
Conversión a PDF
        │
        ▼
Generación opcional de playbook defensivo
```

---

## Salidas generadas

Durante la ejecución, ConfigHunter genera una carpeta de informes dentro del proyecto:

```text
audit/reports/
├── findings.json
├── report.html
├── report.pdf
├── playbook.html
└── playbook.pdf
```

> La carpeta `reports/` está excluida del repositorio mediante `.gitignore`, ya que contiene resultados generados dinámicamente durante cada ejecución.

### Descripción de salidas

| Archivo         | Descripción                                              |
| --------------- | -------------------------------------------------------- |
| `findings.json` | Archivo estructurado con todos los hallazgos detectados. |
| `report.html`   | Informe HTML generado a partir del JSON.                 |
| `report.pdf`    | Informe final en PDF.                                    |
| `playbook.html` | Playbook defensivo en formato HTML.                      |
| `playbook.pdf`  | Playbook defensivo en formato PDF.                       |

---

## Ejemplo de hallazgo

Ejemplo simplificado de hallazgo generado por ConfigHunter:

```json
{
  "id": "CHK-SSH-20",
  "cis_ref": "5.1.20",
  "title": "PermitRootLogin debe estar en 'no'",
  "severity": "critica",
  "evidence": "Línea 180: PermitRootLogin yes",
  "remediation": "PermitRootLogin no",
  "explanation": "Permitir acceso directo como root aumenta el riesgo de compromiso del sistema."
}
```

---

## Playbooks de correlación defensiva

Una de las principales aportaciones de ConfigHunter es el sistema de **playbooks de correlación defensiva**.

Estos documentos amplían determinados hallazgos con información contextual, incluyendo:

* Descripción ampliada del riesgo.
* Importancia defensiva.
* Evidencia detectada.
* Posible explotación.
* Relación con MITRE ATT&CK.
* Fases de Cyber Kill Chain.
* Indicadores DFIR.
* Checklist de análisis.

El objetivo de esta capa es que una configuración insegura no se interprete únicamente como un incumplimiento técnico, sino como una posible debilidad dentro de un escenario real de ataque.

---

## Validación experimental

ConfigHunter fue validado en una máquina virtual **Ubuntu 22.04.5 LTS** mediante tres escenarios controlados.

| Escenario   | Descripción                          | Resultado de ConfigHunter                        |
| ----------- | ------------------------------------ | ------------------------------------------------ |
| Escenario 1 | Configuración base corregida SSH/UFW | 2 hallazgos informativos                         |
| Escenario 2 | SSH inseguro controlado              | 19 hallazgos totales, 18 SSH y 1 UFW informativo |
| Escenario 3 | UFW/firewall inseguro controlado     | 11 hallazgos totales, 10 UFW y 1 SSH informativo |

Además, los resultados se compararon con **Lynis** y **OpenSCAP**, analizando:

* Tiempos de ejecución.
* Cobertura de controles.
* Falsos positivos.
* Falsos negativos.
* Claridad de los hallazgos.
* Calidad de los informes generados.

---

## Resultados destacados

Durante la validación, ConfigHunter completó sus análisis en tiempos inferiores a tres segundos.

| Escenario                                     | Tiempo ConfigHunter |
| --------------------------------------------- | ------------------: |
| Escenario 1: base corregida SSH/UFW           |              1,51 s |
| Escenario 2: SSH inseguro controlado          |              2,98 s |
| Escenario 3: UFW/firewall inseguro controlado |              1,47 s |

### Interpretación de resultados

ConfigHunter no pretende sustituir a herramientas completas de auditoría o cumplimiento como Lynis u OpenSCAP. Su valor diferencial está en ofrecer:

* Auditoría modular.
* Hallazgos claros y específicos.
* Evidencias directas.
* Recomendaciones de remediación.
* Informes comprensibles.
* Contextualización defensiva mediante playbooks.

---

## Comparación conceptual

| Herramienta  | Enfoque                              | Fortaleza principal                             | Limitación principal                                 |
| ------------ | ------------------------------------ | ----------------------------------------------- | ---------------------------------------------------- |
| Lynis        | Auditoría general y hardening        | Amplia cobertura del sistema                    | Salida extensa y necesidad de interpretación técnica |
| OpenSCAP     | Evaluación de cumplimiento           | Uso de perfiles formalizados                    | Mayor complejidad de configuración e interpretación  |
| ConfigHunter | Auditoría modular de configuraciones | Claridad, rapidez y contextualización defensiva | Alcance actual limitado a SSH y UFW                  |

---

## Limitaciones actuales

La versión actual de ConfigHunter presenta algunas limitaciones:

* Cobertura centrada en SSH y UFW.
* No sustituye una auditoría completa del sistema.
* No realiza pruebas ofensivas ni explotación de vulnerabilidades.
* Requiere permisos de administrador para consultar determinadas configuraciones.
* El sistema de playbooks todavía puede ampliarse a más tipos de hallazgos.
* La validación principal se ha realizado en Ubuntu 22.04.5 LTS.

---

## Líneas futuras

Algunas posibles mejoras futuras son:

* Incorporar nuevos módulos de auditoría.
* Añadir controles sobre usuarios, grupos y políticas de contraseñas.
* Revisar permisos de archivos sensibles.
* Analizar servicios activos y puertos expuestos.
* Ampliar la trazabilidad con estándares como CIS Benchmarks o NIST SP 800-53.
* Extender los playbooks a hallazgos de firewall y otros servicios.
* Validar la herramienta en otras distribuciones Linux.
* Incorporar un modo no interactivo para automatización.
* Explorar integraciones con SIEM o dashboards.

---

## Advertencia de uso

ConfigHunter es una herramienta desarrollada con fines académicos y de apoyo a procesos básicos de auditoría y hardening.

Debe utilizarse únicamente en:

* Sistemas propios.
* Laboratorios controlados.
* Entornos donde se disponga de autorización explícita.

El autor no se hace responsable del uso indebido de la herramienta.

---

## Autor

**Iván Seco Martín**
Trabajo Fin de Grado - Ingeniería Informática - Universidad Camilo Jose Cela
2026

---

## Licencia

Este proyecto se distribuye bajo licencia MIT. Consulta el archivo `LICENSE` para más información.
=======
