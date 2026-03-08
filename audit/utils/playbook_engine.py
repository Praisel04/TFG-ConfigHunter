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
MITRE_MAP ={
  "Access_sshd_config": [
    {
      "id": "T1098",
      "name": "Account Manipulation",
      "tactic": "Persistence, Privilege Escalation"
    },
    {
      "id": "T1543",
      "name": "Create or Modify System Process",
      "tactic": "Persistence"
    },
    {
      "id": "T1562.001",
      "name": "Impair Defenses: Disable or Modify Security Tools",
      "tactic": "Defense Evasion"
    }
  ],

  "SSH_PrivateHostKey_Permissions": [
    {
      "id": "T1552.004",
      "name": "Unsecured Credentials: Private Keys",
      "tactic": "Credential Access"
    },
    {
      "id": "T1557",
      "name": "Adversary-in-the-Middle",
      "tactic": "Credential Access, Collection"
    }
  ],

  "DisableForwarding": [
    {
      "id": "T1572",
      "name": "Protocol Tunneling",
      "tactic": "Command and Control"
    },
    {
      "id": "T1090",
      "name": "Proxy",
      "tactic": "Command and Control"
    },
    {
      "id": "T1021.004",
      "name": "Remote Services: SSH",
      "tactic": "Lateral Movement"
    }
  ],

  "GSSAPIAuthentication": [
    {
      "id": "T1550",
      "name": "Use of Alternate Authentication Material",
      "tactic": "Lateral Movement"
    },
    {
      "id": "T1078",
      "name": "Valid Accounts",
      "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion"
    }
  ],

  "KexAlgorithms": [
    {
      "id": "T1557",
      "name": "Adversary-in-the-Middle",
      "tactic": "Credential Access, Collection"
    },
    {
      "id": "T1040",
      "name": "Network Sniffing",
      "tactic": "Credential Access, Discovery"
    }
  ],

  "LoginGraceTime": [
    {
      "id": "T1110",
      "name": "Brute Force",
      "tactic": "Credential Access"
    }
  ],

  "LogLevel": [
    {
      "id": "T1562.002",
      "name": "Impair Defenses: Disable or Modify Security Logging",
      "tactic": "Defense Evasion"
    }
  ],

  "MACs": [
    {
      "id": "T1557",
      "name": "Adversary-in-the-Middle",
      "tactic": "Credential Access, Collection"
    },
    {
      "id": "T1040",
      "name": "Network Sniffing",
      "tactic": "Credential Access, Discovery"
    }
  ],

  "UsePAM": [
    {
      "id": "T1556",
      "name": "Modify Authentication Process",
      "tactic": "Credential Access, Persistence"
    },
    {
      "id": "T1110",
      "name": "Brute Force",
      "tactic": "Credential Access"
    }
  ],

  "PermitRootLogin": [
    {
      "id": "T1078",
      "name": "Valid Accounts",
      "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion"
    },
    {
      "id": "T1110",
      "name": "Brute Force",
      "tactic": "Credential Access"
    },
    {
      "id": "T1021.004",
      "name": "Remote Services: SSH",
      "tactic": "Lateral Movement"
    }
  ],

  "PermitEmptyPasswords": [
    {
      "id": "T1078",
      "name": "Valid Accounts",
      "tactic": "Initial Access, Persistence, Privilege Escalation, Defense Evasion"
    },
    {
      "id": "T1021.004",
      "name": "Remote Services: SSH",
      "tactic": "Lateral Movement"
    }
  ],

  "MaxAuthTries": [
    {
      "id": "T1110",
      "name": "Brute Force",
      "tactic": "Credential Access"
    }
  ],

  "MaxSessions": [
    {
      "id": "T1021.004",
      "name": "Remote Services: SSH",
      "tactic": "Lateral Movement"
    },
    {
      "id": "T1041",
      "name": "Exfiltration Over C2 Channel",
      "tactic": "Exfiltration"
    }
  ],

  "MaxStartups": [
    {
      "id": "T1499",
      "name": "Endpoint Denial of Service",
      "tactic": "Impact"
    }
  ],

  "ClientAliveConfig": [
    {
      "id": "T1071",
      "name": "Application Layer Protocol",
      "tactic": "Command and Control"
    },
    {
      "id": "T1041",
      "name": "Exfiltration Over C2 Channel",
      "tactic": "Exfiltration"
    }
  ],

  "WeakCiphers": [
  {
    "id": "T1557",
    "name": "Adversary-in-the-Middle",
    "tactic": "Credential Access, Collection"
  },
  {
    "id": "T1040",
    "name": "Network Sniffing",
    "tactic": "Credential Access, Discovery"
  }
 ]
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

    "KexAlgorithms": (
        "El uso de algoritmos de intercambio de claves débiles como versiones basadas en SHA-1 "
        "puede permitir ataques de degradación criptográfica o facilitar ataques Man-in-the-Middle. "
        "Un algoritmo KEX inseguro compromete la confidencialidad inicial del túnel SSH, "
        "poniendo en riesgo credenciales y datos transmitidos."
    ),

    "MACs": (
        "El uso de algoritmos MAC débiles (como MD5 o variantes truncadas de SHA1) puede permitir "
        "ataques de integridad o degradación criptográfica. Un MAC inseguro puede facilitar la "
        "manipulación o el análisis del tráfico cifrado, comprometiendo la confidencialidad e "
        "integridad de la sesión SSH."
    ),

    "UsePAM": (
        "Deshabilitar PAM reduce significativamente los controles de autenticación disponibles, "
        "incluyendo políticas de bloqueo, expiración de contraseña, autenticación multifactor "
        "y controles adicionales de seguridad. Esto debilita el proceso de autenticación y "
        "facilita ataques de fuerza bruta o abuso de cuentas comprometidas."
    ),

    "LoginGraceTime": (
        "Un tiempo excesivo antes de cerrar sesiones de autenticación incompletas amplía la ventana "
        "para ataques automatizados de fuerza bruta o enumeración de usuarios. Reducir este valor "
        "limita la capacidad del atacante de probar múltiples combinaciones de credenciales."
    ),

    "LogLevel": (
        "Un nivel de registro insuficiente reduce la visibilidad sobre intentos fallidos de acceso, "
        "movimientos laterales o actividades sospechosas. Esto dificulta la detección temprana de "
        "ataques y facilita la evasión de mecanismos de monitoreo y respuesta."
    ),

    "GSSAPIAuthentication": (
        "Habilitar autenticación GSSAPI puede ampliar la superficie de ataque si no se gestiona "
        "correctamente la infraestructura Kerberos. Un atacante podría abusar de tickets válidos "
        "o configuraciones incorrectas para autenticarse sin necesidad de credenciales adicionales."
    ),

    "AllowUsersGroups": (
        "No restringir explícitamente los usuarios o grupos permitidos para autenticarse mediante SSH "
        "incrementa la superficie de ataque, permitiendo que cualquier cuenta válida del sistema "
        "intente autenticarse remotamente. Limitar usuarios reduce significativamente el riesgo de "
        "compromiso por credenciales robadas."
    ),

    "Banner": (
        "No configurar un banner legal previo a la autenticación elimina una capa disuasoria y "
        "puede dificultar acciones legales posteriores. Aunque no es una vulnerabilidad técnica "
        "directa, forma parte de las buenas prácticas de seguridad y cumplimiento normativo."
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

