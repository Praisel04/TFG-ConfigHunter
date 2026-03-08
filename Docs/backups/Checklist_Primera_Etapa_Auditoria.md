
# ✅ Checklist — Primera Etapa de Desarrollo del Proyecto de Auditoría Automatizada

---

## 🧭 Objetivo general de la primera etapa
Implementar la **versión mínima viable (MVP)** del sistema de auditoría automatizada:
- Detectar configuraciones inseguras básicas.
- Generar resultados estructurados (JSON).
- Crear fichas Markdown a partir de los hallazgos.
- Validar el funcionamiento de los primeros módulos (SSH, usuarios, permisos, firewall, logs).

---

## 📅 Etapa 1 — Planificación y entorno de trabajo

### ✅ Preparación del entorno
- [ ] Instalar **Python 3.11+**
- [ ] Instalar dependencias iniciales: `typer`, `jinja2`, `weasyprint`
- [ ] Crear entorno virtual: `python3 -m venv auditor-env`
- [ ] Activar entorno: `source auditor-env/bin/activate`
- [ ] Configurar repositorio Git local y remoto
- [ ] Crear estructura base del proyecto `/auditor/`
- [ ] Crear archivo `README.md` con objetivos iniciales

---

## ⚙️ Etapa 2 — Arquitectura del sistema

### ✅ Estructura de directorios
- [ ] Crear carpeta `/modules/` para los rastreadores
- [ ] Crear carpeta `/reports/` para los resultados
- [ ] Crear carpeta `/templates/` para PoC y remediaciones
- [ ] Crear carpeta `/utils/` para funciones auxiliares
- [ ] Añadir archivo `config.yml` con opciones básicas

### ✅ Archivos iniciales
- [ ] `main.py` → CLI principal (usando Typer)
- [ ] `modules/__init__.py`
- [ ] `reports/findings.json` → almacenamiento de hallazgos
- [ ] `templates/poc_template.md`
- [ ] `.gitignore` con exclusión de `__pycache__`, `.env`, etc.

---

## 🔍 Etapa 3 — Desarrollo de módulos de auditoría

### ✅ Módulos iniciales a implementar
- [ ] `ssh_check.py` → Detectar configuraciones inseguras de SSH (`PermitRootLogin`, `PasswordAuthentication`, puerto).
- [ ] `users_check.py` → Detectar cuentas sin expiración o sin contraseña.
- [ ] `perms_check.py` → Buscar directorios world-writable o archivos SUID.
- [ ] `firewall_check.py` → Verificar si `ufw` o `iptables` está activo.
- [ ] `logs_check.py` → Validar si `auditd` y `rsyslog` están configurados.

### ✅ Requisitos de cada módulo
- [ ] Retornar resultados en formato JSON.
- [ ] Incluir: ID, título, severidad, evidencia, remediación sugerida, timestamp.
- [ ] Guardar los resultados en `reports/findings.json`.
- [ ] Permitir ejecución independiente para testing (`python3 -m modules.ssh_check`).

---

## 📋 Etapa 4 — Generación de reportes

### ✅ Reportes iniciales
- [ ] Crear función en `utils/reporting.py` para leer `findings.json`.
- [ ] Generar fichas Markdown por hallazgo usando **Jinja2**.
- [ ] Plantilla `poc_template.md` con:
  - Título del hallazgo.
  - Evidencia detectada.
  - Explicación breve.
  - Guía de remediación.
- [ ] Comando CLI: `audit-cli report --format md`
- [ ] Verificar que las fichas se generen correctamente en `/reports/fichas/`.

---

## 🧪 Etapa 5 — Pruebas y validación

### ✅ Testing inicial
- [ ] Probar ejecución de cada módulo por separado.
- [ ] Ejecutar auditoría completa en una VM de laboratorio.
- [ ] Confirmar detección de configuraciones inseguras.
- [ ] Validar formato del archivo `findings.json`.
- [ ] Probar conversión Markdown → PDF con **WeasyPrint**.

### ✅ Pruebas de robustez
- [ ] Comprobar que el sistema no falla si falta un archivo de configuración.
- [ ] Validar funcionamiento con permisos limitados (sin root).
- [ ] Añadir logs básicos de ejecución en consola.

---

## 🧩 Etapa 6 — Documentación y control de versiones

### ✅ Documentación interna
- [ ] Crear `DOCS/estructura_proyecto.md` con descripción de carpetas y módulos.
- [ ] Añadir comentarios y docstrings en todos los módulos.
- [ ] Documentar la API del CLI (`audit-cli --help`).
- [ ] Generar diagrama del flujo general del sistema (ASCII o imagen).

### ✅ Control de versiones
- [ ] Commit inicial del proyecto.
- [ ] Subida del MVP funcional a GitHub.
- [ ] Crear rama `dev` para pruebas y rama `main` para versión estable.
- [ ] Añadir archivo `CHANGELOG.md` para registrar mejoras.

---

## 🚀 Etapa 7 — Objetivo final de esta fase (MVP listo)

- [ ] El sistema puede ejecutar una auditoría completa.
- [ ] Genera un `findings.json` con hallazgos.
- [ ] Crea fichas Markdown por hallazgo.
- [ ] Convierte los reportes a PDF correctamente.
- [ ] Se ejecuta en menos de 2 minutos en una VM Linux.
- [ ] Está documentado y controlado por Git.

---

## 🏁 Resultado esperado de la primera etapa

✅ **Un prototipo funcional (MVP)** que:
- Detecta vulnerabilidades de configuración.  
- Genera reportes claros y reproducibles.  
- Puede demostrarse en laboratorio.  
- Sienta las bases para las próximas fases (PoC, remediaciones automáticas y dashboard).

