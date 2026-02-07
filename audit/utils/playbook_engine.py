# =====================================================================
# PLAYBOOK ENGINE — Motor de análisis DFIR / Threat Hunting / MITRE / KillChain
# =====================================================================

# Este archivo contiene toda la inteligencia necesaria para generar
# Playbooks forenses basados en los hallazgos de la auditoría SSH.
#
# Incluye:
#   - MITRE ATT&CK por hallazgo
#   - Relación con Cyber Kill Chain
#   - Explicación ampliada del hallazgo
#   - Explotación del fallo
#   - Artefactos y logs para DFIR
#   - Checklist de análisis forense
#   - Función enrich_hallazgo() para enriquecer findings.json
# =====================================================================


# ============================================================================
# 1) MITRE ATT&CK MAP
# ============================================================================
MITRE_MAP = {

    # --------------------------------------------------------------
    # 5.1.20 — PermitRootLogin
    # --------------------------------------------------------------
    "PermitRootLogin": [
        {"id": "T1078", "name": "Valid Accounts", "reason": "Acceso directo como root sin necesidad de elevación."},
        {"id": "T1110", "name": "Brute Force", "reason": "Vulnerable a intentos automatizados sobre root."},
        {"id": "T1021", "name": "Remote Services", "reason": "SSH permite acceso total al sistema como root."}
    ],

    # --------------------------------------------------------------
    # 5.1.19 — PermitEmptyPasswords
    # --------------------------------------------------------------
    "PermitEmptyPasswords": [
        {"id": "T1078", "name": "Valid Accounts", "reason": "Cuentas sin contraseña permiten acceso directo."},
        {"id": "T1110", "name": "Brute Force", "reason": "Elimina el proceso de autenticación, facilitando accesos automatizados."},
    ],

    # --------------------------------------------------------------
    # 5.1.6 — Weak Ciphers
    # --------------------------------------------------------------
    "WeakCiphers": [
        {"id": "T1557", "name": "Man-in-the-Middle", "reason": "Cifrados débiles permiten interceptar tráfico SSH."},
        {"id": "T1040", "name": "Network Sniffing", "reason": "Facilita descifrado de sesiones SSH."}
    ],

    # --------------------------------------------------------------
    # 5.1.8 — AllowTcpForwarding
    # --------------------------------------------------------------
    "AllowTcpForwarding": [
        {"id": "T1572", "name": "Protocol Tunneling", "reason": "Permite túneles para pivoting interno."},
        {"id": "T1090", "name": "Proxying", "reason": "El atacante puede enrutar tráfico a otros sistemas internos."}
    ],

    # --------------------------------------------------------------
    # 5.1.16 — MaxAuthTries
    # --------------------------------------------------------------
    "MaxAuthTries": [
        {"id": "T1110", "name": "Brute Force", "reason": "Aumenta ventana para ataques de credenciales automáticos."}
    ],

    # --------------------------------------------------------------
    # 5.1.17 — MaxSessions
    # --------------------------------------------------------------
    "MaxSessions": [
        {"id": "T1021", "name": "Remote Services", "reason": "Permite múltiples conexiones SSH simultáneas."},
        {"id": "T1105", "name": "Exfiltration Over SSH", "reason": "Puede usarse para múltiples flujos de datos paralelos."}
    ],

    # --------------------------------------------------------------
    # 5.1.10 — HostbasedAuthentication
    # --------------------------------------------------------------
    "HostbasedAuthentication": [
        {"id": "T1550", "name": "Use of Trusted Relationships", "reason": "Autenticación basada en confianza entre hosts."},
        {"id": "T1078", "name": "Valid Accounts", "reason": "Un atacante puede abusar del trust inter-host."}
    ],

    # --------------------------------------------------------------
    # 5.1.11 — IgnoreRhosts
    # --------------------------------------------------------------
    "IgnoreRhosts": [
        {"id": "T1550.003", "name": "Exploitation of rhosts", "reason": "rhosts puede ser utilizado para acceso sin contraseña."},
        {"id": "T1078", "name": "Valid Accounts", "reason": "Confianza heredada entre hosts vulnerables."}
    ],

    # --------------------------------------------------------------
    # 5.1.21 — PermitUserEnvironment
    # --------------------------------------------------------------
    "PermitUserEnvironment": [
        {"id": "T1059", "name": "Command Execution", "reason": "Variables maliciosas pueden ejecutar código."},
        {"id": "T1543", "name": "Modify System Processes", "reason": "Puede manipular el entorno de ejecución de SSH."}
    ],

    # --------------------------------------------------------------
    # 5.1.18 — MaxStartups
    # --------------------------------------------------------------
    "MaxStartups": [
        {"id": "T1499", "name": "Denial of Service", "reason": "Valores incorrectos pueden permitir DoS contra SSH."}
    ],

    # --------------------------------------------------------------
    # 5.1.7 — ClientAliveInterval / ClientAliveCountMax
    # --------------------------------------------------------------
    "ClientAliveConfig": [
        {"id": "T1071", "name": "C2 Communication", "reason": "Sesiones largas facilitan canales C2 persistentes."},
        {"id": "T1499", "name": "Resource Exhaustion", "reason": "Sesiones sin límite pueden saturar recursos."}
    ],
}


# ============================================================================
# 2) CYBER KILL CHAIN MAP
# ============================================================================
KILLCHAIN_MAP = {

    "PermitRootLogin": [
        "Reconnaissance", "Exploitation", "Installation", "Command & Control"
    ],

    "PermitEmptyPasswords": [
        "Exploitation", "Installation"
    ],

    "WeakCiphers": [
        "Reconnaissance", "Weaponization", "Exploitation"
    ],

    "AllowTcpForwarding": [
        "Exploitation", "Installation", "Command & Control"
    ],

    "MaxAuthTries": [
        "Reconnaissance", "Exploitation"
    ],

    "MaxSessions": [
        "Installation", "Command & Control", "Actions on Objectives"
    ],

    "HostbasedAuthentication": [
        "Exploitation", "Lateral Movement"
    ],

    "IgnoreRhosts": [
        "Exploitation", "Lateral Movement"
    ],

    "PermitUserEnvironment": [
        "Exploitation", "Installation"
    ],

    "MaxStartups": [
        "Exploitation", "Denial of Service"
    ],

    "ClientAliveConfig": [
        "Installation", "Command & Control"
    ],
}


# ============================================================================
# 3) EXPLICACIÓN EXTENDIDA POR HALLAZGO
# ============================================================================
EXPLANATION_TEXT = {

    "PermitRootLogin": (
        "Habilitar el acceso directo al usuario root permite a un atacante obtener control "
        "total del sistema sin requerir escalada de privilegios. Este es uno de los fallos "
        "más críticos en cualquier sistema Linux."
    ),

    "PermitEmptyPasswords": (
        "Permitir inicios de sesión sin contraseña elimina cualquier barrera de autenticación, "
        "permitiendo accesos automatizados no autorizados. Representa un riesgo crítico."
    ),

    "WeakCiphers": (
        "El uso de cifrados débiles o CBC en SSH aumenta la probabilidad de ataques MITM "
        "y de descifrado parcial del tráfico. Es una vulnerabilidad seria en entornos corporativos."
    ),

    "AllowTcpForwarding": (
        "Permitir túneles SSH facilita el pivoting interno, el acceso a servicios que deberían ser privados "
        "y la exfiltración de datos sin ser detectado por firewalls."
    ),

    "MaxAuthTries": (
        "Un número excesivo de intentos de autenticación permite a un atacante lanzar ataques de fuerza bruta "
        "durante más tiempo sin bloquear la cuenta."
    ),

    "MaxSessions": (
        "Permitir un número elevado de sesiones simultáneas facilita la ejecución paralela de comandos, "
        "exfiltración masiva o múltiples canales C2 dentro del mismo host."
    ),

    "HostbasedAuthentication": (
        "La autenticación basada en confianza entre hosts puede ser manipulada por un atacante para moverse "
        "lateralmente aprovechando relaciones de confianza obsoletas o inseguras."
    ),

    "IgnoreRhosts": (
        "Si el sistema no ignora archivos rhosts, un atacante puede aprovechar configuraciones antiguas para "
        "autenticarse sin contraseña."
    ),

    "PermitUserEnvironment": (
        "Permitir que el usuario cargue variables de entorno puede permitir la inyección de rutas o comandos "
        "maliciosos ejecutados por el servidor SSH."
    ),

    "MaxStartups": (
        "Configuraciones incorrectas pueden permitir ataques DoS mediante creación masiva de conexiones SSH."
    ),

    "ClientAliveConfig": (
        "Valores demasiado altos permiten sesiones persistentes que pueden ser usadas como canales de C2 o "
        "mantener conexiones abiertas para actividades maliciosas."
    ),
}


# ============================================================================
# 4) EXPLOTACIÓN DEL HALLAZGO
# ============================================================================
EXPLOITATION = {

    "PermitRootLogin": (
        "Un atacante puede intentar credenciales filtradas, débiles o comunes para obtener acceso directo "
        "como root, sin necesidad de escalar privilegios."
    ),

    "PermitEmptyPasswords": (
        "El atacante solo necesita identificar un usuario sin contraseña para obtener acceso inmediato al sistema."
    ),

    "WeakCiphers": (
        "Un adversario puede realizar ataques de downgrade, interceptar tráfico o manipular la negociación "
        "del cifrado para obtener información sensible."
    ),

    "AllowTcpForwarding": (
        "El atacante crea túneles SSH para pivotar dentro de la red, exfiltrar datos o acceder a sistemas internos."
    ),

    "MaxAuthTries": (
        "Aumenta la ventana para ataques brute force, permitiendo miles de intentos desde un único origen."
    ),

    "MaxSessions": (
        "Un atacante puede abrir múltiples sesiones para ejecutar tareas paralelas o evadir detección."
    ),

    "HostbasedAuthentication": (
        "El atacante explota relaciones de confianza entre hosts para autenticarse sin contraseña."
    ),

    "IgnoreRhosts": (
        "Si rhosts está permitido, el atacante puede autenticarse desde un host falso configurando un archivo rhosts malicioso."
    ),

    "PermitUserEnvironment": (
        "El atacante introduce variables de entorno maliciosas que alteran rutas de ejecución o cargan código inapropiado."
    ),

    "MaxStartups": (
        "El atacante genera múltiples conexiones simultáneas para saturar SSH y provocar DoS."
    ),

    "ClientAliveConfig": (
        "Un atacante puede mantener sesiones abiertas indefinidamente para establecer canales encubiertos de C2."
    ),
}


# ============================================================================
# 5) INVESTIGACIÓN FORENSE (ARTEFACTOS Y LOGS)
# ============================================================================
FORENSIC = {

    "PermitRootLogin": {
        "logs": ["/var/log/auth.log", "/var/log/secure"],
        "artefacts": [
            "Accesos root desde IPs externas.",
            "Modificación de /root/.ssh/authorized_keys.",
            "Cambios sospechosos en archivos de configuración."
        ]
    },

    "PermitEmptyPasswords": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Inicios de sesión sin contraseña.",
            "Usuarios sin contraseña detectados en /etc/shadow."
        ]
    },

    "WeakCiphers": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Negociación de cifrados débiles.",
            "Mensajes de error relacionados con MAC o algoritmos inseguros."
        ]
    },

    "AllowTcpForwarding": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Forwarded connections detectadas.",
            "Acceso inesperado a puertos internos desde SSH."
        ]
    },

    "MaxAuthTries": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Múltiples intentos fallidos consecutivos desde una misma IP.",
            "Picos de actividad inusual en autenticación."
        ]
    },

    "MaxSessions": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Varios canales SSH abiertos en paralelo.",
            "Sesiones activas persistentes o fuera de horario."
        ]
    },

    "HostbasedAuthentication": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Autenticación basada en host incorrecta.",
            "Accesos desde hosts aparentemente confiables."
        ]
    },

    "IgnoreRhosts": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Uso de rhosts para autenticación.",
            "Intentos de login usando mecanismos obsoletos."
        ]
    },

    "PermitUserEnvironment": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Variables de entorno sospechosas en sesiones SSH.",
            "Cambios en el entorno de ejecución."
        ]
    },

    "MaxStartups": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Excesivas conexiones simultáneas al daemon SSH.",
            "Indicadores de saturación o DoS."
        ]
    },

    "ClientAliveConfig": {
        "logs": ["/var/log/auth.log"],
        "artefacts": [
            "Sesiones inactivas pero persistentes.",
            "Conexiones mantenidas más allá del tiempo esperado."
        ]
    },
}


# ============================================================================
# 6) CHECKLIST DFIR GENERAL
# ============================================================================
CHECKLIST = [
    "¿Hay accesos SSH exitosos desde IPs externas o desconocidas?",
    "¿Se detectan múltiples intentos fallidos consecutivos?",
    "¿Existen modificaciones recientes en authorized_keys?",
    "¿Se han creado nuevos usuarios o claves SSH?",
    "¿Hay procesos sospechosos ejecutándose bajo root?",
    "¿Se han observado sesiones SSH activas fuera de horario?",
    "¿Aparecen túneles SSH o conexiones reenviadas inesperadas?",
]


# ============================================================================
# 7) FUNCIÓN PRINCIPAL — ENRIQUECER HALLAZGO
# ============================================================================
def enrich_hallazgo(hallazgo):
    """
    Recibe un hallazgo de findings.json y lo convierte en un
    hallazgo ampliado para el Playbook.
    """
    title = hallazgo.get("title")

    enriched = hallazgo.copy()
    enriched["mitre"] = MITRE_MAP.get(title, [])
    enriched["killchain"] = KILLCHAIN_MAP.get(title, [])
    enriched["explanation_ext"] = EXPLANATION_TEXT.get(title, "")
    enriched["exploitation"] = EXPLOITATION.get(title, "")
    enriched["forensic"] = FORENSIC.get(title, {})
    enriched["checklist"] = CHECKLIST

    return enriched

