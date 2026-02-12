from jinja2 import Environment, FileSystemLoader, select_autoescape
from pathlib import Path
import json
import re

def build_extended_remediation(finding):
    """
    Motor profesional v5 con validación enriquecida.
    Genera:
    - impacto
    - pasos detallados
    - comando de validación
    - resultado esperado
    """

    title = finding.get("title", "").lower()
    evidence = finding.get("evidence", "").lower()
    remediation = finding.get("remediation", "")
    explanation = finding.get("explanation", "")

    impacto = explanation if explanation else "Este hallazgo representa un riesgo significativo."

    # Lista de parámetros SSH reconocidos
    parametros = [
        "allowusers", "allowgroups", "banner",
        "clientaliveinterval", "clientalivecountmax",
        "ciphers", "allowtcpforwarding", "gssapiauthentication",
        "hostbasedauthentication", "ignorerhosts",
        "loglevel", "logingracetime", "maxauthtries",
        "maxsessions", "permitemptypasswords", "permitrootlogin",
        "permituserenvironment", "usepam", "maxstartups", "kexalgorithms"
    ]

    param_detectado = None

    # 1. detectar en evidence
    for p in parametros:
        if p in evidence:
            param_detectado = p
            break

    # 2. detectar en remediacion
    if not param_detectado:
        for p in parametros:
            if p in remediation.lower():
                param_detectado = p
                break

    # 3. detectar en title
    if not param_detectado:
        for p in parametros:
            if p in title:
                param_detectado = p
                break

    # ============================================================
    # PLANTILLAS ESPECÍFICAS
    # ============================================================

    # Regla de permisos inseguros
    if "permisos" in title or "permission" in evidence:
        pasos = f"""
1. Revisar permisos actuales:
   sudo ls -l /etc/ssh/

2. Aplicar permisos seguros típicos:
   sudo chmod 600 /etc/ssh/ssh_host_*
   sudo chown root:root /etc/ssh/ssh_host_*

3. Seguir las recomendaciones exactas:
   {remediation}

4. Recargar SSH (si aplica):
   sudo systemctl restart sshd
"""

        validacion = """
Validación:
   sudo stat -c "%a %U %G" /etc/ssh/ssh_host_*
"""
        resultado = "Los archivos deben ser propiedad de root:root y con permisos 600."
        return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

    # -----------------------
    # Banner
    if param_detectado == "banner":
        pasos = """
1. Editar o crear el banner:
   sudo nano /etc/issue.net

2. Añadir texto legal corporativo.

3. Configurar SSH para usarlo:
   sudo nano /etc/ssh/sshd_config
   Banner /etc/issue.net

4. Recargar SSH:
   sudo systemctl restart sshd
"""
        validacion = "sudo sshd -T | grep banner"
        resultado = "Debe aparecer: banner /etc/issue.net"
        return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

    # -----------------------
    # ClientAlive*
    if param_detectado in ("clientaliveinterval", "clientalivecountmax"):
        pasos = f"""
1. Editar SSH:
   sudo nano /etc/ssh/sshd_config

2. Localizar:
   {evidence}

3. Cambiar por:
   {remediation}

4. Recargar:
   sudo systemctl restart sshd
"""
        validacion = "sshd -T | grep clientalive"
        resultado = f"Debe verse: {remediation}"
        return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

    # -----------------------
    # Parámetros SSH simples
    if param_detectado in parametros:
        pasos = f"""
1. Editar archivo SSH:
   sudo nano /etc/ssh/sshd_config

2. Localizar:
   {evidence}

3. Aplicar la recomendación:
   {remediation}

4. Recargar SSH:
   sudo systemctl restart sshd
"""
        validacion = f"sudo sshd -T | grep {param_detectado}"
        resultado = f"Debe aparecer: {remediation.split()[0]} {remediation.split()[1]}"
        return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

    # ============================================================
    #                          MOTOR UFW V3 
    # ============================================================

    if finding["id"].startswith("UFW-"):

        rule = evidence.strip().lower()

        # -------------------------
        # Función auxiliar interna
        # -------------------------
        def grep_port(p):
            return f"sudo ufw status verbose | grep -E \"^{p}(/tcp|/udp)?\\s\""

        # -------------------------
        # Detect port, protocol, CIDR, origin
        # -------------------------
        puerto = None
        protocolo = None

        m = re.search(r"(\d{1,5})(?:/(tcp|udp))?", rule)
        if m:
            puerto = m.group(1)
            protocolo = m.group(2)

        cidr = None
        m2 = re.search(r"/(\d{1,2})", rule)
        if m2:
            try:
                cidr = int(m2.group(1))
            except:
                cidr = None

        origen = None
        if "anywhere" in rule:
            origen = "Anywhere"
        if "0.0.0.0/0" in rule:
            origen = "0.0.0.0/0"
        if "::/0" in rule:
            origen = "::/0"

        # ============================================================
        #  UFW-101 — Firewall desactivado
        # ============================================================
        if finding["id"] == "UFW-101":
            pasos = f"""
1. Activar el firewall UFW:
   sudo ufw enable

2. Configurar políticas seguras:
   sudo ufw default deny incoming
   sudo ufw default allow outgoing

3. Habilitar logging seguro:
   sudo ufw logging on
"""
            validacion = "sudo ufw status verbose"
            resultado = "Debe mostrarse: Status: active"
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-102 — Política incoming incorrecta
        # ============================================================
        if finding["id"] == "UFW-102":
            pasos = """
1. Establecer política segura:
   sudo ufw default deny incoming
"""
            validacion = "sudo ufw status verbose | grep 'deny (incoming)'"
            resultado = "Debe mostrarse: Default: deny (incoming)"
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-103 — Política outgoing incorrecta
        # ============================================================
        if finding["id"] == "UFW-103":
            pasos = """
1. Establecer política recomendada:
   sudo ufw default allow outgoing
"""
            validacion = "sudo ufw status verbose | grep 'allow (outgoing)'"
            resultado = "Debe mostrarse: Default: allow (outgoing)"
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-104 — Logging OFF
        # ============================================================
        if finding["id"] == "UFW-104":
            pasos = """
1. Activar logging:
   sudo ufw logging on
"""
            validacion = "sudo ufw status verbose | grep 'Logging:'"
            resultado = "Debe mostrarse: Logging: on"
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-201 — SSH expuesto (IPv4 / IPv6)
        # ============================================================
        if finding["id"] == "UFW-201-HARDENING":
            pasos = f"""
1. Restringir acceso SSH a IP específica:
   sudo ufw delete <número_regla>
   sudo ufw allow from <IP_segura> to any port 22
"""
            validacion = grep_port("22")
            resultado = "Solo deben aparecer reglas SSH restringidas a IPs concretas."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-301 — ALLOW sin LIMIT
        # ============================================================
        if finding["id"] == "UFW-301-HARDENING":
            pasos = f"""
1. Convertir ALLOW en LIMIT:
   sudo ufw delete <número_regla>
   sudo ufw limit {puerto}/tcp
"""
            validacion = grep_port(puerto)
            resultado = f"La regla debe aparecer como LIMIT para el puerto {puerto}."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-302 — ANY/ANY
        # ============================================================
        if finding["id"] == "UFW-302-HARDENING":
            pasos = f"""
1. Eliminar regla demasiado permisiva:
   sudo ufw delete <número_regla>

2. Aplicar reglas restringidas:
   sudo ufw allow from <IP_segura> to any port {puerto}
"""
            validacion = f"sudo ufw status verbose | grep 'Anywhere'"
            resultado = "No debe aparecer ningún origen 'Anywhere'."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-303 — Exposición total 0.0.0.0/0 o ::/0
        # ============================================================
        if finding["id"] == "UFW-303-HARDENING":
            pasos = f"""
1. Eliminar regla expuesta públicamente:
   sudo ufw delete <número_regla>

2. Volver a crearla de forma segura:
   sudo ufw allow from <IP_segura> to any port {puerto}
"""
            validacion = "sudo ufw status verbose | grep '/0'"
            resultado = "No debe haber reglas con origen 0.0.0.0/0 o ::/0."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-304 — CIDR demasiado amplio
        # ============================================================
        if finding["id"] == "UFW-304-HARDENING":
            pasos = f"""
1. Identificar rango peligroso:
   {evidence}

2. Cambiar a una máscara más segura (ej /24):
   sudo ufw delete <número_regla>
   sudo ufw allow from <IP_segura>/24 to any port {puerto}
"""
            validacion = f"sudo ufw status verbose | grep '{puerto}'"
            resultado = "La máscara debe ser /24 o más restrictiva."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-305 — Regla sin puerto definido
        # ============================================================
        if finding["id"] == "UFW-305-HARDENING":
            pasos = f"""
1. Regla incompleta detectada:
   {evidence}

2. Recrear correctamente la regla indicando el puerto.
"""
            validacion = "sudo ufw status verbose"
            resultado = "Todas las reglas deben especificar un puerto."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-401 — Duplicadas
        # ============================================================
        if finding["id"] == "UFW-401-HARDENING":
            pasos = """
1. Eliminar reglas duplicadas:
   sudo ufw status numbered
   sudo ufw delete <num>
"""
            validacion = "sudo ufw status numbered"
            resultado = "No deben existir reglas duplicadas."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

        # ============================================================
        #  UFW-402 — Conflicto allow/deny
        # ============================================================
        if finding["id"] == "UFW-402-HARDENING":
            pasos = """
1. Revisar conflicto en el puerto.

2. Mantener solo UNA política:
   - ALLOW o DENY
"""
            validacion = grep_port(puerto)
            resultado = "El puerto no debe tener reglas contradictorias."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}


        # ============================================================
        #  UFW-403 — Falta de protocolo
        # ============================================================
        if finding["id"] == "UFW-403-HARDENING":
            pasos = f"""
1. Reglas sin protocolo detectadas:
   {evidence}

2. Recrear especificando tcp/udp:
   sudo ufw allow {puerto}/tcp
"""
            validacion = grep_port(puerto)
            resultado = "Las reglas deben mostrar el protocolo explícitamente."
            return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}

    
    
    # -----------------------
    # Fallback genérico
    pasos = f"""
1. Revisar evidencia:
   {evidence}

2. Aplicar la recomendación:
   {remediation}
"""
    validacion = "Validación manual requerida."
    resultado = "Debe verificarse que el servicio funcione y el cambio está aplicado."

    return {"impacto": impacto, "pasos": pasos, "validacion": validacion, "resultado": resultado}


def generate_html_report(module_name="ALL"):
    """
    Genera el informe HTML completo, incluyendo:
    - Portada
    - Índice
    - Resumen
    - Hallazgos
    - Remediaciones detalladas
    - Conclusión
    """

    # Paths base
    base_path = Path(__file__).resolve().parent.parent
    templates_path = base_path / "templates"
    reports_path = base_path / "reports"
    findings_path = reports_path / "findings.json"

    # Archivo HTML de salida
    if module_name == "ALL":
        output_filename = "report.html"
    else:
        output_filename = f"{module_name}_Report.html"

    output_path = reports_path / output_filename

    # Verificar que existe findings.json
    if not findings_path.exists():
        print("❌ No se encontró reports/findings.json. Ejecuta primero un escaneo.")
        return

    # ---------------------------------------------
    # 1. Cargar datos del JSON
    # ---------------------------------------------

    with open(findings_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Asegurar campos requeridos
    generated_on = data.get("generated_on", "")
    system_name = data.get("system_name", "Sistema no especificado")
    summary = data.get("summary", {})
    modules = data.get("modules", [])
    conclusion = data.get("conclusion", {})

    # Añadir explicación por defecto si falta
    # Asegurar explicación y construir remediación extendida
    for module in modules:
        for finding in module["findings"]:
            
            # Explicación por defecto si falta
            if "explanation" not in finding:
                finding["explanation"] = "No se ha definido una explicación detallada para este hallazgo."

            # Construcción automática de remediación extendida
            finding["extended"] = build_extended_remediation(finding)



    # ---------------------------------------------
    # 2. Configurar entorno Jinja
    # ---------------------------------------------

    env = Environment(
        loader=FileSystemLoader(str(templates_path)),
        autoescape=select_autoescape(["html", "xml"])
    )

    # Render plantilla base
    template = env.get_template("base.html")

    rendered_html = template.render(
        generated_on=generated_on,
        system_name=system_name,
        summary=summary,
        modules=modules,
        conclusion=conclusion
    )

    # ---------------------------------------------
    # 3. Guardar HTML final
    # ---------------------------------------------

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered_html)

    print(f"✔ Informe HTML generado correctamente en: {output_path}")


if __name__ == "__main__":
    generate_html_report()
