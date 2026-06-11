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

    "Access_sshd_config": [
        {
            "id": "T1098",
            "name": "Account Manipulation",
            "tactic": "Persistence, Privilege Escalation"
        },
        {
            "id": "T1543",
            "name": "Create or Modify System Process",
            "tactic": "Persistence, Privilege Escalation"
        },
        {
            "id": "T1562.001",
            "name": "Impair Defenses: Disable or Modify Tools",
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

    "AllowTcpForwarding": [
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
            "name": "Use Alternate Authentication Material",
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
            "id": "T1562",
            "name": "Impair Defenses",
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
            "id": "T1556.003",
            "name": "Modify Authentication Process: Pluggable Authentication Modules",
            "tactic": "Credential Access, Persistence, Defense Evasion"
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
    ],

    "AllowUsersGroups": [
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

    "Banner": []
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
        "Reconnaissance", "Exploitation", "Installation"
    ],

    "IgnoreRhosts": [
        "Reconnaissance", "Exploitation"
    ],

    "PermitUserEnvironment": [
        "Exploitation", "Installation"
    ],

    "MaxStartups": [
        "Exploitation", "Actions on Objectives"
    ],

    "ClientAliveConfig": [
        "Installation", "Command & Control"
    ],

    "KexAlgorithms": [
        "Reconnaissance", "Weaponization", "Exploitation"
    ],

    "MACs": [
        "Reconnaissance", "Weaponization", "Exploitation"
    ],

    "UsePAM": [
        "Exploitation", "Installation"
    ],

    "LoginGraceTime": [
        "Reconnaissance", "Exploitation"
    ],

    "LogLevel": [
        "Exploitation", "Actions on Objectives"
    ],

    "GSSAPIAuthentication": [
        "Reconnaissance", "Exploitation", "Installation"
    ],

    "AllowUsersGroups": [
        "Reconnaissance", "Exploitation"
    ],

    "Banner": [
        "Reconnaissance"
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

    "KexAlgorithms": (
        "Un adversario puede intentar forzar el uso de algoritmos de intercambio de claves débiles "
        "para facilitar ataques de degradación criptográfica o ataques Man-in-the-Middle durante "
        "el establecimiento de la sesión SSH."
    ),

    "MACs": (
        "Un atacante puede aprovechar algoritmos MAC débiles para intentar manipular, degradar o "
        "analizar la integridad del tráfico SSH, aumentando el riesgo de alteración o exposición "
        "de información transmitida durante la sesión."
    ),

    "UsePAM": (
        "Si PAM está deshabilitado, un atacante puede beneficiarse de la ausencia de controles "
        "adicionales de autenticación, como políticas de bloqueo, expiración de contraseñas o "
        "mecanismos de autenticación reforzada."
    ),

    "LoginGraceTime": (
        "Un tiempo de gracia elevado permite mantener conexiones de autenticación abiertas durante "
        "más tiempo, facilitando intentos automatizados de fuerza bruta, enumeración de usuarios o "
        "saturación del servicio SSH."
    ),

    "LogLevel": (
        "Un nivel de registro insuficiente puede permitir que un atacante reduzca su visibilidad "
        "durante intentos de acceso, movimientos laterales o actividades sospechosas, dificultando "
        "la detección y posterior investigación."
    ),

    "GSSAPIAuthentication": (
        "Un atacante podría abusar de configuraciones GSSAPI o Kerberos mal gestionadas para intentar "
        "autenticarse mediante tickets válidos, credenciales comprometidas o relaciones de confianza "
        "incorrectamente configuradas."
    ),

    "AllowUsersGroups": (
        "Si no se restringen usuarios o grupos permitidos por SSH, cualquier cuenta válida del sistema "
        "puede convertirse en objetivo de ataques de fuerza bruta, credenciales filtradas o accesos "
        "no autorizados."
    ),

    "Banner": (
        "La ausencia de banner no facilita directamente la explotación técnica, pero elimina una "
        "advertencia legal previa al acceso y puede debilitar la posición defensiva o normativa ante "
        "usos no autorizados del sistema."
    ),
}


# ============================================================================
# 5) INVESTIGACIÓN FORENSE (ARTEFACTOS Y LOGS)
# ============================================================================
FORENSIC = {

    "PermitRootLogin": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/root/.ssh/authorized_keys",
            "/root/.bash_history",
            "/var/log/auth.log"
        ],
        "commands": [
            "grep -i 'Accepted' /var/log/auth.log | grep -i root",
            "last root",
            "lastb root",
            "stat /root/.ssh/authorized_keys"
        ],
        "indicators": [
            "Accesos SSH exitosos como root desde IPs externas o desconocidas.",
            "Modificación reciente de /root/.ssh/authorized_keys.",
            "Sesiones root fuera del horario habitual.",
            "Intentos fallidos seguidos de un acceso exitoso como root."
        ],
        "notes": (
            "PermitRootLogin habilitado incrementa el impacto de credenciales comprometidas, "
            "ya que permite acceso directo con máximos privilegios sin escalada posterior."
        )
    },

    "PermitEmptyPasswords": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/ssh/sshd_config"
        ],
        "commands": [
            "sudo awk -F: '($2==\"\"){print $1}' /etc/shadow",
            "grep -i 'Accepted' /var/log/auth.log",
            "last",
            "lastb"
        ],
        "indicators": [
            "Usuarios con campo de contraseña vacío en /etc/shadow.",
            "Inicios de sesión exitosos en cuentas sin contraseña.",
            "Accesos remotos a usuarios no esperados.",
            "Intentos automatizados contra múltiples cuentas locales."
        ],
        "notes": (
            "La presencia de usuarios sin contraseña debe considerarse crítica. "
            "No siempre habrá una línea explícita indicando 'login sin contraseña', por lo que "
            "debe revisarse /etc/shadow junto con los eventos de autenticación."
        )
    },

    "WeakCiphers": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config"
        ],
        "commands": [
            "sshd -T | grep -i ciphers",
            "grep -i '^Ciphers' /etc/ssh/sshd_config",
            "nmap --script ssh2-enum-algos -p 22 localhost"
        ],
        "indicators": [
            "Cifrados CBC o algoritmos obsoletos habilitados.",
            "Clientes antiguos negociando algoritmos débiles.",
            "Posible exposición a ataques de degradación criptográfica.",
            "Anomalías de conexión compatibles con intentos de downgrade."
        ],
        "notes": (
            "La negociación exacta de cifrados no siempre queda registrada por defecto en auth.log. "
            "Para confirmar algoritmos ofrecidos por el servidor es más fiable usar sshd -T o herramientas "
            "de enumeración como nmap ssh2-enum-algos."
        )
    },

    "AllowTcpForwarding": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "~/.ssh/config",
            "~/.ssh/authorized_keys"
        ],
        "commands": [
            "sshd -T | grep -i allowtcpforwarding",
            "ss -tnp",
            "lsof -i -n -P | grep ssh",
            "ps aux | grep '[s]sh'"
        ],
        "indicators": [
            "Conexiones SSH con túneles locales, remotos o dinámicos.",
            "Acceso a puertos internos a través de sesiones SSH.",
            "Procesos SSH manteniendo conexiones persistentes no justificadas.",
            "Uso de SSH como canal de pivoting o evasión de controles de red."
        ],
        "notes": (
            "Los túneles SSH no siempre quedan registrados de forma detallada en auth.log. "
            "Debe complementarse la revisión con conexiones activas, procesos y puertos abiertos."
        )
    },

    "MaxAuthTries": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": ["/etc/ssh/sshd_config"],
        "commands": [
            "sshd -T | grep -i maxauthtries",
            "grep -i 'Failed password' /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr",
            "lastb"
        ],
        "indicators": [
            "Múltiples intentos fallidos consecutivos desde una misma IP.",
            "Intentos contra múltiples usuarios en poco tiempo.",
            "Patrones compatibles con fuerza bruta o password spraying.",
            "Accesos exitosos posteriores a numerosos fallos."
        ],
        "notes": (
            "Un MaxAuthTries elevado aumenta la ventana de ataque antes del cierre de conexión, "
            "por lo que debe correlacionarse con intentos fallidos y accesos exitosos."
        )
    },

    "MaxSessions": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": ["/etc/ssh/sshd_config"],
        "commands": [
            "sshd -T | grep -i maxsessions",
            "who",
            "w",
            "ss -tnp | grep ssh",
            "ps aux | grep '[s]shd:'"
        ],
        "indicators": [
            "Múltiples sesiones SSH simultáneas del mismo usuario.",
            "Sesiones interactivas y no interactivas abiertas en paralelo.",
            "Actividad persistente fuera de horario.",
            "Uso de múltiples canales para ejecución paralela o transferencia de datos."
        ],
        "notes": (
            "MaxSessions afecta al número de sesiones multiplexadas por conexión. "
            "La evidencia debe revisarse junto con sesiones activas, procesos y conexiones."
        )
    },

    "HostbasedAuthentication": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/hosts.equiv",
            "/etc/ssh/shosts.equiv",
            "~/.rhosts",
            "~/.shosts",
            "/etc/ssh/ssh_known_hosts"
        ],
        "commands": [
            "sshd -T | grep -i hostbasedauthentication",
            "find /home -name '.rhosts' -o -name '.shosts' 2>/dev/null",
            "ls -la /etc/hosts.equiv /etc/ssh/shosts.equiv 2>/dev/null"
        ],
        "indicators": [
            "Accesos desde hosts marcados como confiables.",
            "Existencia de archivos .rhosts o .shosts en directorios de usuario.",
            "Relaciones de confianza antiguas o no documentadas.",
            "Autenticaciones no basadas en contraseña desde hosts internos."
        ],
        "notes": (
            "La autenticación basada en host depende de relaciones de confianza. "
            "La investigación debe centrarse en hosts confiables, archivos equivalentes y accesos laterales."
        )
    },

    "IgnoreRhosts": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/hosts.equiv",
            "~/.rhosts",
            "~/.shosts"
        ],
        "commands": [
            "sshd -T | grep -i ignorerhosts",
            "find /home -name '.rhosts' -o -name '.shosts' 2>/dev/null",
            "ls -la /etc/hosts.equiv 2>/dev/null"
        ],
        "indicators": [
            "Presencia de archivos .rhosts o .shosts.",
            "Autenticaciones basadas en mecanismos heredados.",
            "Relaciones de confianza no autorizadas entre hosts.",
            "Accesos desde equipos internos sin justificación operativa."
        ],
        "notes": (
            "Los archivos rhosts son mecanismos obsoletos y peligrosos. "
            "Aunque no siempre generen eventos explícitos, su mera presencia debe investigarse."
        )
    },

    "PermitUserEnvironment": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh"],
        "files": [
            "/etc/ssh/sshd_config",
            "~/.ssh/environment",
            "~/.ssh/authorized_keys",
            "/etc/environment"
        ],
        "commands": [
            "sshd -T | grep -i permituserenvironment",
            "find /home -path '*/.ssh/environment' -type f 2>/dev/null",
            "grep -R 'environment=' /home/*/.ssh/authorized_keys 2>/dev/null"
        ],
        "indicators": [
            "Variables de entorno definidas por usuarios en sesiones SSH.",
            "Uso de environment= dentro de authorized_keys.",
            "Alteración de rutas de ejecución como PATH, LD_PRELOAD o LD_LIBRARY_PATH.",
            "Comportamientos anómalos al iniciar sesión por SSH."
        ],
        "notes": (
            "Permitir variables de entorno controladas por usuario puede facilitar manipulación "
            "del entorno de ejecución. Revisar especialmente variables relacionadas con carga de librerías."
        )
    },

    "MaxStartups": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/syslog"],
        "files": ["/etc/ssh/sshd_config"],
        "commands": [
            "sshd -T | grep -i maxstartups",
            "grep -i 'connection' /var/log/auth.log | grep -i ssh",
            "ss -tan | grep ':22' | wc -l"
        ],
        "indicators": [
            "Número elevado de conexiones simultáneas al puerto SSH.",
            "Conexiones no autenticadas acumuladas.",
            "Mensajes de rechazo o cierre de conexión por saturación.",
            "Patrones compatibles con denegación de servicio contra SSH."
        ],
        "notes": (
            "MaxStartups controla conexiones no autenticadas simultáneas. "
            "Su mala configuración puede facilitar saturación del servicio."
        )
    },

    "ClientAliveConfig": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh"],
        "files": ["/etc/ssh/sshd_config"],
        "commands": [
            "sshd -T | grep -i clientalive",
            "who",
            "w",
            "last",
            "ss -tnp | grep ssh"
        ],
        "indicators": [
            "Sesiones SSH persistentes durante periodos anómalos.",
            "Conexiones inactivas mantenidas durante más tiempo del esperado.",
            "Sesiones abiertas fuera de horario laboral.",
            "Posibles canales persistentes usados para C2 o administración no autorizada."
        ],
        "notes": (
            "ClientAliveInterval y ClientAliveCountMax deben analizarse juntos. "
            "Valores demasiado altos pueden permitir persistencia de sesiones inactivas."
        )
    },

    "KexAlgorithms": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config"
        ],
        "commands": [
            "sshd -T | grep -i kexalgorithms",
            "grep -i '^KexAlgorithms' /etc/ssh/sshd_config",
            "nmap --script ssh2-enum-algos -p 22 localhost"
        ],
        "indicators": [
            "Algoritmos KEX obsoletos o basados en SHA-1 habilitados.",
            "Servidor ofreciendo intercambio de claves débil.",
            "Riesgo de degradación criptográfica en el establecimiento del canal.",
            "Posibles intentos de Man-in-the-Middle en la negociación inicial."
        ],
        "notes": (
            "La negociación KEX rara vez queda detallada en logs por defecto. "
            "La evidencia principal debe obtenerse mediante configuración efectiva o enumeración de algoritmos."
        )
    },

    "MACs": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/ssh/ssh_config"
        ],
        "commands": [
            "sshd -T | grep -i macs",
            "grep -i '^MACs' /etc/ssh/sshd_config",
            "nmap --script ssh2-enum-algos -p 22 localhost"
        ],
        "indicators": [
            "Algoritmos MAC débiles habilitados.",
            "Servidor ofreciendo mecanismos de integridad obsoletos.",
            "Riesgo de degradación o manipulación de integridad en sesiones SSH.",
            "Anomalías relacionadas con negociación criptográfica."
        ],
        "notes": (
            "Igual que con los cifrados y KEX, los MACs ofrecidos deben validarse con sshd -T "
            "o enumeración externa. Los logs por defecto pueden no ser suficientes."
        )
    },

    "UsePAM": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/pam.d/sshd",
            "/etc/security/faillock.conf",
            "/etc/security/pwquality.conf",
            "/etc/security/access.conf"
        ],
        "commands": [
            "sshd -T | grep -i usepam",
            "grep -i pam /var/log/auth.log",
            "cat /etc/pam.d/sshd"
        ],
        "indicators": [
            "Ausencia de eventos PAM esperados durante autenticaciones SSH.",
            "No aplicación de políticas de bloqueo o complejidad de contraseña.",
            "Autenticaciones exitosas sin controles adicionales definidos en PAM.",
            "Debilitamiento de controles de acceso, MFA o expiración de credenciales."
        ],
        "notes": (
            "UsePAM deshabilitado reduce visibilidad y controles de autenticación. "
            "Debe revisarse junto con la configuración de /etc/pam.d/sshd y políticas de seguridad asociadas."
        )
    },

    "LoginGraceTime": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": ["/etc/ssh/sshd_config"],
        "commands": [
            "sshd -T | grep -i logingracetime",
            "grep -i 'Failed password' /var/log/auth.log",
            "grep -i 'timeout' /var/log/auth.log"
        ],
        "indicators": [
            "Conexiones de autenticación incompletas mantenidas durante periodos prolongados.",
            "Intentos reiterados sin finalizar sesión.",
            "Patrones compatibles con enumeración de usuarios.",
            "Actividad automatizada contra el servicio SSH."
        ],
        "notes": (
            "Un tiempo de gracia elevado amplía la ventana para ataques automatizados antes "
            "de que el servidor cierre la conexión."
        )
    },

    "LogLevel": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/syslog"],
        "files": ["/etc/ssh/sshd_config"],
        "commands": [
            "sshd -T | grep -i loglevel",
            "grep -i '^LogLevel' /etc/ssh/sshd_config",
            "journalctl -u ssh --since '24 hours ago'"
        ],
        "indicators": [
            "Nivel de registro insuficiente para reconstruir actividad SSH.",
            "Ausencia de detalle en accesos fallidos o exitosos.",
            "Dificultad para correlacionar actividad sospechosa.",
            "Pérdida de trazabilidad ante una investigación posterior."
        ],
        "notes": (
            "LogLevel no suele ser un indicador de compromiso por sí mismo, sino una condición "
            "que reduce la visibilidad forense. Debe tratarse como debilidad de monitorización."
        )
    },

    "GSSAPIAuthentication": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure", "/var/log/krb5.log"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/krb5.conf",
            "/tmp/krb5cc_*"
        ],
        "commands": [
            "sshd -T | grep -i gssapiauthentication",
            "klist",
            "ls -la /tmp/krb5cc_* 2>/dev/null",
            "grep -i gssapi /var/log/auth.log"
        ],
        "indicators": [
            "Intentos de autenticación mediante GSSAPI o Kerberos.",
            "Uso de tickets Kerberos asociados a sesiones SSH.",
            "Tickets Kerberos inesperados en /tmp.",
            "Accesos desde dominios, hosts o principales no esperados."
        ],
        "notes": (
            "GSSAPIAuthentication solo es relevante si el entorno utiliza Kerberos o autenticación integrada. "
            "/var/log/krb5.log puede no existir en todos los sistemas."
        )
    },

    "AllowUsersGroups": {
        "logs": ["/var/log/auth.log", "journalctl -u ssh", "/var/log/secure"],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/passwd",
            "/etc/group"
        ],
        "commands": [
            "sshd -T | grep -Ei 'allowusers|allowgroups'",
            "cut -d: -f1 /etc/passwd",
            "last",
            "lastb"
        ],
        "indicators": [
            "Intentos de autenticación con cuentas no destinadas a acceso remoto.",
            "Accesos SSH de usuarios del sistema o cuentas de servicio.",
            "Aumento de superficie de ataque por ausencia de restricciones.",
            "Uso de cuentas válidas comprometidas para acceso remoto."
        ],
        "notes": (
            "La ausencia de AllowUsers o AllowGroups no implica compromiso por sí misma, "
            "pero amplía el conjunto de cuentas que pueden ser atacadas remotamente."
        )
    },

    "Banner": {
        "logs": [],
        "files": [
            "/etc/ssh/sshd_config",
            "/etc/issue.net",
            "/etc/issue"
        ],
        "commands": [
            "sshd -T | grep -i banner",
            "grep -i '^Banner' /etc/ssh/sshd_config",
            "cat /etc/issue.net 2>/dev/null"
        ],
        "indicators": [
            "Ausencia de banner legal previo a la autenticación.",
            "Falta de advertencia formal sobre uso autorizado.",
            "Debilidad documental en procesos de cumplimiento o respuesta legal."
        ],
        "notes": (
            "Banner no debe tratarse como indicador técnico de compromiso. "
            "Su relevancia es principalmente legal, normativa y de buenas prácticas."
        )
    },
}


# ============================================================================
# 6) CHECKLIST DFIR GENERAL
# ============================================================================
CHECKLIST_COMMON = [
    {
        "category": "Autenticación",
        "question": "¿Hay accesos SSH exitosos desde IPs externas o desconocidas?",
        "why": (
            "Permite comprobar si existe actividad de acceso real al sistema desde orígenes "
            "no esperados o no autorizados."
        ),
        "commands": [
            "grep -i 'Accepted' /var/log/auth.log",
            "journalctl -u ssh | grep -i 'Accepted'",
            "last"
        ],
        "if_found": (
            "Si aparecen accesos desde IPs no reconocidas, se debe revisar el usuario afectado, "
            "la hora de conexión, la duración de la sesión y la actividad posterior."
        ),
        "if_not_found": (
            "Si no aparecen accesos sospechosos, no hay evidencia directa de explotación mediante "
            "inicio de sesión exitoso, aunque conviene revisar intentos fallidos."
        )
    },

    {
        "category": "Autenticación",
        "question": "¿Se detectan múltiples intentos fallidos consecutivos desde una misma IP o contra varios usuarios?",
        "why": (
            "Permite identificar actividad compatible con fuerza bruta, password spraying "
            "o enumeración de usuarios."
        ),
        "commands": [
            "grep -i 'Failed password' /var/log/auth.log",
            "journalctl -u ssh | grep -i 'Failed password'",
            "lastb"
        ],
        "if_found": (
            "Si existen muchos intentos fallidos desde un mismo origen o contra múltiples usuarios, "
            "puede existir actividad maliciosa previa a un posible acceso."
        ),
        "if_not_found": (
            "Si no aparecen intentos fallidos relevantes, no hay evidencias claras de fuerza bruta "
            "en los registros disponibles."
        )
    },

    {
        "category": "Persistencia",
        "question": "¿Existen modificaciones recientes en archivos authorized_keys?",
        "why": (
            "Permite detectar si se han añadido claves SSH para mantener acceso persistente "
            "sin necesidad de contraseña."
        ),
        "commands": [
            "find /home /root -path '*/.ssh/authorized_keys' -exec stat {} \\; 2>/dev/null",
            "find /home /root -path '*/.ssh/authorized_keys' -exec ls -la {} \\; 2>/dev/null"
        ],
        "if_found": (
            "Si hay modificaciones recientes, se deben revisar las claves añadidas, el usuario afectado "
            "y si la fecha coincide con accesos sospechosos."
        ),
        "if_not_found": (
            "Si no hay modificaciones recientes, no hay indicios directos de persistencia mediante "
            "authorized_keys."
        )
    },

    {
        "category": "Cuentas locales",
        "question": "¿Se han creado usuarios, grupos o claves SSH recientemente?",
        "why": (
            "Permite detectar posibles acciones de persistencia mediante creación de cuentas "
            "o habilitación de nuevos accesos."
        ),
        "commands": [
            "grep -Ei 'useradd|adduser|new user|new group' /var/log/auth.log",
            "tail -n 20 /etc/passwd",
            "lastlog"
        ],
        "if_found": (
            "Si aparecen usuarios o grupos creados recientemente sin justificación, se debe revisar "
            "quién ejecutó la acción y si la cuenta tiene acceso SSH o privilegios elevados."
        ),
        "if_not_found": (
            "Si no se observan nuevas cuentas, no hay evidencia directa de persistencia por creación "
            "de usuarios."
        )
    },

    {
        "category": "Sesiones",
        "question": "¿Se observan sesiones SSH activas, persistentes o fuera del horario habitual?",
        "why": (
            "Permite identificar conexiones que podrían estar siendo utilizadas para mantener acceso "
            "o realizar actividad interactiva no autorizada."
        ),
        "commands": [
            "who",
            "w",
            "last",
            "ss -tnp | grep ssh"
        ],
        "if_found": (
            "Si existen sesiones activas no justificadas, se debe revisar el usuario, origen, proceso asociado "
            "y comandos ejecutados durante la sesión."
        ),
        "if_not_found": (
            "Si no hay sesiones sospechosas, no hay evidencia actual de acceso interactivo persistente."
        )
    },

    {
        "category": "Red",
        "question": "¿Aparecen túneles SSH, conexiones reenviadas o conexiones persistentes inesperadas?",
        "why": (
            "Permite detectar uso de SSH como canal de pivoting, evasión de firewall, exfiltración "
            "o comunicación encubierta."
        ),
        "commands": [
            "ss -tnp | grep ssh",
            "lsof -i -n -P | grep ssh",
            "ps aux | grep '[s]sh'"
        ],
        "if_found": (
            "Si aparecen conexiones reenviadas o procesos SSH persistentes no esperados, se debe investigar "
            "si existe tunelización, pivoting o acceso a servicios internos."
        ),
        "if_not_found": (
            "Si no se observan conexiones sospechosas, no hay evidencia activa de túneles SSH en el momento "
            "de la revisión."
        )
    }
]

# ============================================================================
# 7) CHECKLIST DFIR ESPECIFICO
# ============================================================================

# ============================================================================
# 7) CHECKLIST DFIR ESPECÍFICO POR HALLAZGO
# ============================================================================
CHECKLIST_BY_FINDING = {

    "PermitRootLogin": [
        {
            "category": "Acceso privilegiado",
            "question": "¿Se han producido accesos SSH exitosos directamente como root?",
            "why": (
                "Permite comprobar si la configuración insegura ha sido aprovechada para acceder "
                "directamente con máximos privilegios."
            ),
            "review": [
                "Eventos de autenticación aceptada para el usuario root.",
                "IP de origen, fecha, hora y duración de la conexión.",
                "Relación entre intentos fallidos previos y acceso exitoso posterior."
            ],
            "if_found": (
                "Si aparecen accesos exitosos como root desde orígenes no reconocidos, el hallazgo debe "
                "tratarse como posible compromiso crítico."
            ),
            "if_not_found": (
                "Si no aparecen accesos root sospechosos, no hay evidencia directa de explotación, "
                "aunque la configuración sigue siendo crítica y debe corregirse."
            )
        },
        {
            "category": "Persistencia",
            "question": "¿Se han añadido o modificado claves SSH en /root/.ssh/authorized_keys?",
            "why": (
                "Permite detectar si un atacante ha intentado mantener acceso persistente sobre la cuenta root."
            ),
            "review": [
                "Fecha de modificación de /root/.ssh/authorized_keys.",
                "Claves públicas no reconocidas o añadidas recientemente.",
                "Coincidencia temporal entre la modificación del archivo y accesos SSH sospechosos."
            ],
            "if_found": (
                "Si existen claves nuevas o no autorizadas, se debe investigar el origen del cambio, "
                "eliminar la clave y revisar toda la actividad posterior asociada a root."
            ),
            "if_not_found": (
                "Si no hay modificaciones recientes ni claves desconocidas, no hay indicios directos "
                "de persistencia mediante claves SSH en root."
            )
        },
        {
            "category": "Actividad posterior",
            "question": "¿Existen cambios o actividad sospechosa ejecutada con privilegios de root?",
            "why": (
                "Permite valorar si un posible acceso como root derivó en acciones posteriores sobre el sistema."
            ),
            "review": [
                "Cambios recientes en archivos críticos de configuración.",
                "Procesos ejecutados bajo el usuario root sin justificación.",
                "Historial o evidencias de comandos administrativos recientes."
            ],
            "if_found": (
                "Si se detectan cambios no justificados bajo root, se debe ampliar la investigación a persistencia, "
                "movimiento lateral, modificación de servicios y posible exfiltración."
            ),
            "if_not_found": (
                "Si no se observan cambios posteriores relevantes, no hay evidencia clara de acciones post-acceso, "
                "aunque el riesgo de la configuración permanece."
            )
        }
    ],

    "PermitEmptyPasswords": [
        {
            "category": "Credenciales",
            "question": "¿Existen cuentas locales sin contraseña configurada?",
            "why": (
                "Permite comprobar si la configuración insegura puede haber dejado cuentas accesibles "
                "sin barrera real de autenticación."
            ),
            "review": [
                "Usuarios con campo de contraseña vacío en /etc/shadow.",
                "Cuentas con shell interactiva habilitada.",
                "Cuentas locales que no deberían permitir acceso remoto."
            ],
            "if_found": (
                "Si aparecen usuarios sin contraseña, se debe bloquear o corregir esas cuentas de forma inmediata "
                "y revisar si han sido utilizadas recientemente."
            ),
            "if_not_found": (
                "Si no hay usuarios sin contraseña, no hay evidencia directa de explotación por esta vía, "
                "aunque la directiva insegura debe corregirse."
            )
        },
        {
            "category": "Uso de cuentas",
            "question": "¿Alguna cuenta sin contraseña ha iniciado sesión recientemente?",
            "why": (
                "Permite relacionar la mala configuración con actividad real de autenticación."
            ),
            "review": [
                "Últimos accesos de los usuarios afectados.",
                "Origen de las sesiones recientes.",
                "Actividad posterior asociada a dichas cuentas."
            ],
            "if_found": (
                "Si una cuenta sin contraseña ha iniciado sesión, debe tratarse como posible acceso no autorizado "
                "y revisarse la actividad completa de esa cuenta."
            ),
            "if_not_found": (
                "Si no hay accesos recientes de esas cuentas, no hay evidencia directa de explotación, "
                "pero la configuración sigue representando un riesgo crítico."
            )
        },
        {
            "category": "Exposición remota",
            "question": "¿Las cuentas sin contraseña tienen posibilidad real de autenticarse por SSH?",
            "why": (
                "Permite determinar si el riesgo local se convierte en una exposición remota explotable."
            ),
            "review": [
                "Restricciones AllowUsers o AllowGroups.",
                "Estado de la cuenta en /etc/passwd y /etc/shadow.",
                "Shell asignada a la cuenta y permisos de acceso remoto."
            ],
            "if_found": (
                "Si una cuenta sin contraseña puede acceder por SSH, el riesgo debe priorizarse como crítico."
            ),
            "if_not_found": (
                "Si las cuentas no pueden acceder remotamente, el riesgo práctico se reduce, "
                "pero la existencia de cuentas sin contraseña debe corregirse igualmente."
            )
        }
    ],

    "WeakCiphers": [
        {
            "category": "Criptografía",
            "question": "¿El servidor SSH ofrece cifrados débiles durante la negociación?",
            "why": (
                "Permite validar si la debilidad detectada está realmente expuesta a clientes remotos."
            ),
            "review": [
                "Lista efectiva de cifrados ofrecidos por el servicio SSH.",
                "Presencia de cifrados CBC u otros algoritmos obsoletos.",
                "Diferencias entre el archivo de configuración y la configuración activa del servicio."
            ],
            "if_found": (
                "Si el servidor ofrece cifrados débiles, se confirma exposición criptográfica y debe "
                "priorizarse la eliminación de algoritmos inseguros."
            ),
            "if_not_found": (
                "Si no se ofrecen cifrados débiles en la configuración efectiva, puede tratarse de una regla "
                "no activa, una configuración no cargada o un falso positivo a revisar."
            )
        },
        {
            "category": "Compatibilidad",
            "question": "¿La configuración mantiene cifrados débiles por compatibilidad con clientes antiguos?",
            "why": (
                "Permite identificar si la debilidad responde a una necesidad real o a una configuración heredada."
            ),
            "review": [
                "Necesidad operativa de clientes SSH antiguos.",
                "Historial de conexiones de clientes legacy.",
                "Alternativas seguras para sustituir compatibilidad criptográfica obsoleta."
            ],
            "if_found": (
                "Si existen clientes antiguos que requieren cifrados débiles, se debe planificar su actualización "
                "o aislamiento antes de endurecer definitivamente la configuración."
            ),
            "if_not_found": (
                "Si no hay dependencia real de clientes antiguos, los cifrados débiles deben eliminarse sin demora."
            )
        },
        {
            "category": "Exposición",
            "question": "¿El servicio SSH está expuesto en redes donde un ataque de intermediario sería plausible?",
            "why": (
                "Permite valorar la probabilidad práctica de explotación mediante degradación criptográfica o MITM."
            ),
            "review": [
                "Exposición del servicio SSH a Internet.",
                "Uso desde redes compartidas, públicas o no confiables.",
                "Alertas de red, cambios de clave de host o conexiones anómalas."
            ],
            "if_found": (
                "Si SSH está expuesto en redes no confiables, la remediación criptográfica debe priorizarse."
            ),
            "if_not_found": (
                "Si SSH solo está expuesto en redes controladas, el riesgo práctico puede ser menor, "
                "aunque la configuración debe endurecerse igualmente."
            )
        }
    ],

    "AllowTcpForwarding": [
        {
            "category": "Túneles SSH",
            "question": "¿Existen conexiones SSH compatibles con redirección de puertos?",
            "why": (
                "Permite comprobar si la capacidad de forwarding ha podido ser usada para crear túneles."
            ),
            "review": [
                "Conexiones persistentes asociadas a procesos SSH.",
                "Puertos locales o remotos abiertos de forma inesperada.",
                "Sesiones SSH con comportamiento compatible con tunelización."
            ],
            "if_found": (
                "Si aparecen conexiones reenviadas o puertos extraños, se debe investigar posible pivoting, "
                "acceso interno o canal encubierto."
            ),
            "if_not_found": (
                "Si no aparecen túneles activos, no hay evidencia actual de abuso de forwarding, "
                "aunque la configuración debe restringirse."
            )
        },
        {
            "category": "Acceso interno",
            "question": "¿Se ha accedido a servicios internos a través de una sesión SSH?",
            "why": (
                "Permite detectar si SSH ha sido utilizado para saltar restricciones de red o firewalls."
            ),
            "review": [
                "Conexiones desde localhost hacia servicios internos.",
                "Puertos internos consultados durante sesiones SSH.",
                "Relación temporal entre sesiones SSH y actividad hacia servicios privados."
            ],
            "if_found": (
                "Si se detecta acceso a servicios internos mediante SSH, se debe analizar el alcance del pivoting "
                "y revisar las credenciales usadas."
            ),
            "if_not_found": (
                "Si no se detecta acceso interno mediante forwarding, no hay evidencia directa de explotación por esta vía."
            )
        },
        {
            "category": "Persistencia de canal",
            "question": "¿Hay sesiones SSH largas o procesos persistentes compatibles con forwarding?",
            "why": (
                "Permite identificar posibles canales mantenidos para C2, administración no autorizada o exfiltración."
            ),
            "review": [
                "Duración anómala de sesiones SSH.",
                "Procesos ssh/sshd persistentes.",
                "Conexiones salientes asociadas a sesiones SSH."
            ],
            "if_found": (
                "Si se observan sesiones persistentes con conexiones asociadas, deben revisarse como posible canal encubierto."
            ),
            "if_not_found": (
                "Si no hay sesiones persistentes sospechosas, no hay evidencia actual de abuso mediante forwarding."
            )
        }
    ],

    "MaxAuthTries": [
        {
            "category": "Fuerza bruta",
            "question": "¿Se observan muchos intentos fallidos antes del cierre de conexión?",
            "why": (
                "Permite comprobar si un número elevado de intentos ha facilitado ataques automatizados."
            ),
            "review": [
                "Cantidad de fallos por origen.",
                "Usuarios atacados repetidamente.",
                "Ventanas temporales con alta concentración de intentos fallidos."
            ],
            "if_found": (
                "Si se observan muchos fallos repetidos, puede existir actividad de fuerza bruta aprovechando "
                "una ventana de autenticación amplia."
            ),
            "if_not_found": (
                "Si no hay patrones de fallo relevantes, no hay evidencia de abuso reciente, "
                "aunque reducir el valor sigue siendo recomendable."
            )
        },
        {
            "category": "Password spraying",
            "question": "¿Los intentos fallidos se distribuyen entre múltiples usuarios?",
            "why": (
                "Permite distinguir ataques contra una cuenta concreta de intentos de password spraying."
            ),
            "review": [
                "Número de usuarios objetivo.",
                "Frecuencia de intentos por usuario.",
                "Repetición de IPs o rangos de origen."
            ],
            "if_found": (
                "Si se detecta spraying, se deben revisar las cuentas afectadas y comprobar si alguna tuvo acceso exitoso."
            ),
            "if_not_found": (
                "Si no hay distribución entre múltiples cuentas, no se observa un patrón claro de password spraying."
            )
        },
        {
            "category": "Compromiso posterior",
            "question": "¿Tras varios fallos aparece algún acceso exitoso desde el mismo origen?",
            "why": (
                "Permite identificar una posible transición entre intentos fallidos y acceso comprometido."
            ),
            "review": [
                "Secuencia temporal entre fallos y accesos exitosos.",
                "Coincidencia de IP de origen.",
                "Usuario finalmente autenticado."
            ],
            "if_found": (
                "Si hay acceso exitoso tras numerosos fallos, debe tratarse como acceso sospechoso y revisarse actividad posterior."
            ),
            "if_not_found": (
                "Si no hay acceso exitoso posterior, no hay evidencia directa de compromiso, aunque sí puede haber intento de ataque."
            )
        }
    ],

    "MaxSessions": [
        {
            "category": "Sesiones múltiples",
            "question": "¿Existen varias sesiones SSH simultáneas del mismo usuario u origen?",
            "why": (
                "Permite identificar uso de sesiones paralelas para ejecución de tareas, evasión o persistencia operativa."
            ),
            "review": [
                "Usuarios con varias sesiones simultáneas.",
                "Origen de las conexiones.",
                "Duración y solapamiento temporal de sesiones."
            ],
            "if_found": (
                "Si existen muchas sesiones simultáneas no justificadas, debe revisarse la actividad del usuario."
            ),
            "if_not_found": (
                "Si no hay sesiones simultáneas sospechosas, no hay evidencia directa de abuso de esta configuración."
            )
        },
        {
            "category": "Transferencia de datos",
            "question": "¿Las sesiones múltiples coinciden con actividad de transferencia o conexiones inusuales?",
            "why": (
                "Permite valorar si se han usado varias sesiones para mover o extraer información."
            ),
            "review": [
                "Procesos de transferencia como scp, sftp o rsync.",
                "Picos de actividad de red durante las sesiones.",
                "Conexiones salientes asociadas al usuario."
            ],
            "if_found": (
                "Si se detecta transferencia inusual, debe investigarse posible exfiltración o copia masiva."
            ),
            "if_not_found": (
                "Si no hay actividad de transferencia asociada, no hay evidencia directa de exfiltración mediante sesiones múltiples."
            )
        },
        {
            "category": "Persistencia operativa",
            "question": "¿Se mantienen sesiones no interactivas o multiplexadas durante mucho tiempo?",
            "why": (
                "Permite detectar canales mantenidos para control persistente o administración no autorizada."
            ),
            "review": [
                "Sesiones sin actividad aparente.",
                "Procesos sshd asociados a usuarios concretos.",
                "Horarios no habituales de conexión."
            ],
            "if_found": (
                "Si hay sesiones largas sin justificación, deben revisarse procesos, origen y comandos ejecutados."
            ),
            "if_not_found": (
                "Si no hay sesiones persistentes, no hay evidencia de abuso por multiplexación o permanencia."
            )
        }
    ],

    "HostbasedAuthentication": [
        {
            "category": "Relaciones de confianza",
            "question": "¿Existen archivos o reglas que autoricen hosts confiables?",
            "why": (
                "Permite comprobar si la autenticación basada en host podría ser utilizada sin credenciales interactivas."
            ),
            "review": [
                "Archivos hosts.equiv, shosts.equiv, .rhosts o .shosts.",
                "Hosts y usuarios autorizados.",
                "Fechas de modificación de relaciones de confianza."
            ],
            "if_found": (
                "Si existen relaciones de confianza no documentadas, deben revisarse y eliminarse si no están justificadas."
            ),
            "if_not_found": (
                "Si no existen relaciones de confianza, no hay evidencia directa de abuso mediante autenticación basada en host."
            )
        },
        {
            "category": "Movimiento lateral",
            "question": "¿Hay accesos SSH desde hosts internos o confiables no esperados?",
            "why": (
                "Permite identificar si un atacante ha podido moverse desde otro sistema considerado confiable."
            ),
            "review": [
                "Origen de sesiones SSH recientes.",
                "Direcciones internas o nombres de host confiables.",
                "Usuarios autenticados desde esos hosts."
            ],
            "if_found": (
                "Si aparecen accesos desde hosts confiables no esperados, el host origen debe investigarse como posible punto comprometido."
            ),
            "if_not_found": (
                "Si no hay accesos desde hosts confiables sospechosos, no hay evidencia directa de movimiento lateral por esta vía."
            )
        },
        {
            "category": "Integridad de confianza",
            "question": "¿Las claves o relaciones de confianza han cambiado recientemente?",
            "why": (
                "Permite detectar manipulación de confianza entre sistemas o posible suplantación."
            ),
            "review": [
                "Cambios recientes en ssh_known_hosts.",
                "Alertas de cambio de clave de host.",
                "Entradas nuevas o modificadas en archivos de confianza."
            ],
            "if_found": (
                "Si existen cambios no documentados, deben validarse las claves y revisar posible suplantación o MITM."
            ),
            "if_not_found": (
                "Si no hay cambios recientes, no hay indicios claros de manipulación de relaciones de confianza."
            )
        }
    ],

    "IgnoreRhosts": [
        {
            "category": "Mecanismos heredados",
            "question": "¿Existen archivos .rhosts, .shosts o hosts.equiv en el sistema?",
            "why": (
                "Permite identificar mecanismos heredados de confianza que podrían permitir autenticación insegura."
            ),
            "review": [
                "Ubicación de archivos .rhosts y .shosts.",
                "Contenido de hosts.equiv o equivalentes.",
                "Permisos y propietario de esos archivos."
            ],
            "if_found": (
                "Si existen estos archivos, debe revisarse su contenido y eliminar cualquier relación no justificada."
            ),
            "if_not_found": (
                "Si no se encuentran estos archivos, no hay evidencia directa de abuso mediante rhosts."
            )
        },
        {
            "category": "Hosts autorizados",
            "question": "¿El contenido de esos archivos permite hosts o usuarios no documentados?",
            "why": (
                "Permite determinar si las relaciones heredadas podrían ser usadas por un atacante."
            ),
            "review": [
                "Entradas con comodines o hosts amplios.",
                "Usuarios autorizados por esos archivos.",
                "Relación con hosts realmente administrados."
            ],
            "if_found": (
                "Si aparecen hosts o usuarios no documentados, deben tratarse como riesgo de acceso no autorizado."
            ),
            "if_not_found": (
                "Si no hay entradas no documentadas, no se observan indicios claros de abuso de confianza heredada."
            )
        },
        {
            "category": "Actividad relacionada",
            "question": "¿Hay accesos desde hosts definidos en archivos rhosts o equivalentes?",
            "why": (
                "Permite comprobar si esos mecanismos han sido utilizados en accesos reales."
            ),
            "review": [
                "Eventos de acceso desde hosts listados.",
                "Usuarios autenticados desde esos orígenes.",
                "Coincidencia temporal con cambios en los archivos."
            ],
            "if_found": (
                "Si hay accesos desde hosts definidos en estos archivos, se debe investigar el origen y el usuario afectado."
            ),
            "if_not_found": (
                "Si no hay actividad relacionada, no hay evidencia directa de explotación reciente."
            )
        }
    ],

    "PermitUserEnvironment": [
        {
            "category": "Entorno de ejecución",
            "question": "¿Existen variables de entorno controladas por usuario en sesiones SSH?",
            "why": (
                "Permite detectar manipulación del entorno de ejecución en sesiones remotas."
            ),
            "review": [
                "Archivos .ssh/environment.",
                "Variables como PATH, LD_PRELOAD o LD_LIBRARY_PATH.",
                "Fechas de modificación de archivos de entorno."
            ],
            "if_found": (
                "Si aparecen variables peligrosas, debe revisarse si permiten cargar rutas, librerías o comandos no autorizados."
            ),
            "if_not_found": (
                "Si no aparecen variables controladas por usuario, no hay evidencia directa de abuso de esta opción."
            )
        },
        {
            "category": "Claves SSH",
            "question": "¿Se usan opciones environment= dentro de authorized_keys?",
            "why": (
                "Permite detectar persistencia o manipulación del entorno asociada a claves SSH."
            ),
            "review": [
                "Claves SSH con opciones environment=.",
                "Usuarios afectados.",
                "Relación con comandos forzados o restricciones de clave."
            ],
            "if_found": (
                "Si se detectan opciones environment= no justificadas, deben eliminarse y revisarse los accesos asociados."
            ),
            "if_not_found": (
                "Si no aparecen opciones environment=, no hay evidencia directa de abuso mediante authorized_keys."
            )
        },
        {
            "category": "Comportamiento anómalo",
            "question": "¿Las sesiones SSH muestran diferencias de entorno o ejecución inesperadas?",
            "why": (
                "Permite identificar efectos prácticos de una manipulación del entorno."
            ),
            "review": [
                "Errores o comportamientos extraños al iniciar sesión.",
                "Comandos ejecutados con rutas anómalas.",
                "Diferencias entre entorno esperado y entorno de sesión."
            ],
            "if_found": (
                "Si hay comportamientos anómalos, se debe investigar posible carga de código o rutas manipuladas."
            ),
            "if_not_found": (
                "Si no hay anomalías observables, no hay evidencia directa de explotación mediante entorno de usuario."
            )
        }
    ],

    "MaxStartups": [
        {
            "category": "Disponibilidad",
            "question": "¿Se observan muchas conexiones no autenticadas simultáneas al servicio SSH?",
            "why": (
                "Permite valorar si la configuración pudo ser aprovechada para saturar el daemon SSH."
            ),
            "review": [
                "Volumen de conexiones al puerto SSH.",
                "Conexiones acumuladas sin autenticación completa.",
                "Mensajes de rechazo, cierre o saturación del servicio."
            ],
            "if_found": (
                "Si hay muchas conexiones no autenticadas, puede existir actividad compatible con denegación de servicio."
            ),
            "if_not_found": (
                "Si no se observa saturación, no hay evidencia actual de abuso, aunque el parámetro debe endurecerse."
            )
        },
        {
            "category": "Origen del tráfico",
            "question": "¿Las conexiones proceden de una misma IP, rango o ubicación no esperada?",
            "why": (
                "Permite distinguir entre un problema operativo y una actividad dirigida contra SSH."
            ),
            "review": [
                "IPs de origen repetidas.",
                "Rangos de red con alta frecuencia de conexión.",
                "Patrones temporales de conexión anómalos."
            ],
            "if_found": (
                "Si se identifica un origen dominante sospechoso, se debe bloquear o investigar según criticidad."
            ),
            "if_not_found": (
                "Si no hay origen dominante, no se observa un patrón claro de ataque dirigido."
            )
        },
        {
            "category": "Impacto",
            "question": "¿Hubo degradación o indisponibilidad del servicio SSH?",
            "why": (
                "Permite relacionar la mala configuración con un impacto real sobre la disponibilidad."
            ),
            "review": [
                "Errores de conexión de usuarios legítimos.",
                "Alertas o reinicios del servicio SSH.",
                "Quejas o eventos operativos de indisponibilidad."
            ],
            "if_found": (
                "Si hay impacto confirmado, debe tratarse como incidente de disponibilidad."
            ),
            "if_not_found": (
                "Si no hay impacto operativo, no hay evidencia de explotación efectiva, aunque existe riesgo preventivo."
            )
        }
    ],

    "ClientAliveConfig": [
        {
            "category": "Persistencia de sesión",
            "question": "¿Existen sesiones SSH inactivas mantenidas durante periodos anómalos?",
            "why": (
                "Permite comprobar si la configuración facilita sesiones persistentes."
            ),
            "review": [
                "Duración de sesiones SSH.",
                "Sesiones aparentemente inactivas.",
                "Horarios no habituales de conexión."
            ],
            "if_found": (
                "Si existen sesiones largas e inactivas, debe revisarse usuario, origen y procesos asociados."
            ),
            "if_not_found": (
                "Si no existen sesiones persistentes sospechosas, no hay evidencia directa de abuso reciente."
            )
        },
        {
            "category": "Canal persistente",
            "question": "¿Las sesiones largas mantienen conexiones de red o procesos activos?",
            "why": (
                "Permite valorar si una sesión persistente puede actuar como canal de control."
            ),
            "review": [
                "Procesos asociados a sesiones SSH.",
                "Conexiones salientes mantenidas.",
                "Actividad periódica o automatizada."
            ],
            "if_found": (
                "Si hay conexiones o procesos asociados a sesiones largas, debe investigarse posible C2 o administración no autorizada."
            ),
            "if_not_found": (
                "Si no hay procesos o conexiones sospechosas, no hay indicios claros de canal persistente."
            )
        },
        {
            "category": "Política de cierre",
            "question": "¿Las sesiones se cierran conforme a la política esperada?",
            "why": (
                "Permite validar si los valores ClientAliveInterval y ClientAliveCountMax son efectivos."
            ),
            "review": [
                "Configuración efectiva de ClientAliveInterval.",
                "Configuración efectiva de ClientAliveCountMax.",
                "Sesiones antiguas aún activas."
            ],
            "if_found": (
                "Si las sesiones no se cierran correctamente, se deben ajustar los valores de tiempo y recuento."
            ),
            "if_not_found": (
                "Si las sesiones se cierran correctamente, no hay evidencia de abuso de persistencia por timeout."
            )
        }
    ],

    "KexAlgorithms": [
        {
            "category": "Criptografía",
            "question": "¿El servidor ofrece algoritmos de intercambio de claves débiles u obsoletos?",
            "why": (
                "Confirma si la debilidad está expuesta durante la negociación inicial del canal SSH."
            ),
            "review": [
                "Configuración efectiva de KEX.",
                "Algoritmos basados en SHA-1 o grupos obsoletos.",
                "Diferencia entre archivo de configuración y configuración activa."
            ],
            "if_found": (
                "Si se ofrecen algoritmos KEX débiles, se confirma exposición criptográfica y debe corregirse la lista permitida."
            ),
            "if_not_found": (
                "Si no se confirma exposición en la configuración efectiva, puede tratarse de una directiva no activa."
            )
        },
        {
            "category": "Compatibilidad",
            "question": "¿La configuración permite clientes antiguos por compatibilidad no justificada?",
            "why": (
                "Permite valorar si la presencia de algoritmos débiles responde a una necesidad real o heredada."
            ),
            "review": [
                "Necesidad real de clientes antiguos.",
                "Historial de conexiones de clientes legacy.",
                "Dependencias operativas que requieran algoritmos antiguos."
            ],
            "if_found": (
                "Si existen clientes antiguos, debe planificarse su actualización o aislamiento."
            ),
            "if_not_found": (
                "Si no existe necesidad operativa clara, la compatibilidad débil debe eliminarse."
            )
        },
        {
            "category": "Exposición",
            "question": "¿El servicio SSH está expuesto en redes donde un intermediario sería plausible?",
            "why": (
                "Ayuda a valorar la probabilidad real de explotación mediante degradación criptográfica."
            ),
            "review": [
                "Exposición del servicio SSH a Internet.",
                "Uso desde redes compartidas o no confiables.",
                "Alertas de red o cambios de clave de host."
            ],
            "if_found": (
                "Si SSH está expuesto en redes no confiables, la remediación debe priorizarse."
            ),
            "if_not_found": (
                "Si solo está expuesto en redes controladas, el riesgo práctico puede ser menor, "
                "pero debe corregirse."
            )
        }
    ],

    "MACs": [
        {
            "category": "Criptografía",
            "question": "¿El servidor SSH ofrece algoritmos MAC débiles o mecanismos de integridad obsoletos?",
            "why": (
                "Permite comprobar si la integridad de la sesión SSH puede verse debilitada."
            ),
            "review": [
                "MACs efectivos ofrecidos por el servidor.",
                "Algoritmos truncados, MD5 o SHA1 débiles.",
                "Política criptográfica aplicada."
            ],
            "if_found": (
                "Si se ofrecen MACs débiles, se debe actualizar la configuración para permitir únicamente algoritmos robustos."
            ),
            "if_not_found": (
                "Si no se ofrecen MACs débiles, no hay evidencia de exposición criptográfica activa por esta vía."
            )
        },
        {
            "category": "Anomalías criptográficas",
            "question": "¿Hay errores o anomalías relacionados con negociación o integridad SSH?",
            "why": (
                "Permite detectar indicios indirectos de problemas en la negociación criptográfica."
            ),
            "review": [
                "Eventos de desconexión anómalos.",
                "Errores de negociación SSH.",
                "Repetición de anomalías desde los mismos orígenes."
            ],
            "if_found": (
                "Si hay anomalías repetidas, deben investigarse los orígenes y endurecer la política criptográfica."
            ),
            "if_not_found": (
                "Si no hay anomalías, no se observan indicios de abuso activo."
            )
        },
        {
            "category": "Coherencia de política",
            "question": "¿Ciphers, KEX y MACs están alineados con una política criptográfica segura?",
            "why": (
                "Evita corregir un algoritmo dejando otros mecanismos criptográficos débiles."
            ),
            "review": [
                "Conjunto completo de algoritmos SSH.",
                "Consistencia con las recomendaciones de hardening.",
                "Configuración efectiva tras reinicio del servicio."
            ],
            "if_found": (
                "Si existen otras debilidades criptográficas, debe corregirse la política completa."
            ),
            "if_not_found": (
                "Si no hay debilidades adicionales, la corrección puede centrarse en el hallazgo detectado."
            )
        }
    ],

    "UsePAM": [
        {
            "category": "Autenticación",
            "question": "¿Se están aplicando controles PAM durante el acceso SSH?",
            "why": (
                "Permite comprobar si las políticas adicionales de autenticación están activas."
            ),
            "review": [
                "Estado efectivo de UsePAM.",
                "Eventos PAM durante autenticaciones SSH.",
                "Configuración de /etc/pam.d/sshd."
            ],
            "if_found": (
                "Si no se aplican controles PAM, deben reactivarse y validarse las políticas asociadas."
            ),
            "if_not_found": (
                "Si PAM está activo y los eventos son coherentes, no hay evidencia directa de abuso."
            )
        },
        {
            "category": "Bloqueo de cuentas",
            "question": "¿Se aplican bloqueos o límites ante intentos fallidos?",
            "why": (
                "Permite valorar si la ausencia de PAM facilita ataques de fuerza bruta."
            ),
            "review": [
                "Políticas faillock, tally o equivalentes.",
                "Fallos repetidos sin bloqueo aparente.",
                "Usuarios atacados repetidamente."
            ],
            "if_found": (
                "Si no existen bloqueos efectivos, debe configurarse una política de protección ante fuerza bruta."
            ),
            "if_not_found": (
                "Si los bloqueos funcionan, no hay evidencia directa de abuso por ausencia de control PAM."
            )
        },
        {
            "category": "Controles adicionales",
            "question": "¿Se han omitido MFA, expiración o restricciones de acceso por no usar PAM?",
            "why": (
                "Permite identificar pérdida de controles defensivos asociados al sistema PAM."
            ),
            "review": [
                "Módulos PAM esperados.",
                "Políticas de acceso, calidad y expiración.",
                "Diferencias entre política esperada y política aplicada."
            ],
            "if_found": (
                "Si se omiten controles esperados, debe restaurarse PAM y documentar la desviación."
            ),
            "if_not_found": (
                "Si no se observan controles omitidos, no hay impacto directo visible, aunque UsePAM debe estar habilitado."
            )
        }
    ],

    "LoginGraceTime": [
        {
            "category": "Autenticación",
            "question": "¿Hay conexiones incompletas mantenidas durante periodos largos?",
            "why": (
                "Permite evaluar si el tiempo de gracia facilita actividad automatizada previa a la autenticación."
            ),
            "review": [
                "Eventos de timeout o conexiones incompletas.",
                "Duración de intentos preautenticados.",
                "Repetición por IP de origen."
            ],
            "if_found": (
                "Si hay muchos intentos incompletos o timeouts, puede existir abuso de la ventana de autenticación."
            ),
            "if_not_found": (
                "Si no hay patrones anómalos, no hay evidencia directa de abuso reciente."
            )
        },
        {
            "category": "Enumeración",
            "question": "¿Existen patrones compatibles con enumeración de usuarios?",
            "why": (
                "Permite detectar intentos automatizados para descubrir cuentas válidas."
            ),
            "review": [
                "Intentos contra usuarios inexistentes.",
                "Variación rápida de nombres de usuario.",
                "Mensajes de error repetidos en autenticación."
            ],
            "if_found": (
                "Si hay enumeración, se debe investigar el origen y aplicar medidas de bloqueo."
            ),
            "if_not_found": (
                "Si no hay variación de usuarios, no se observa un patrón claro de enumeración."
            )
        },
        {
            "category": "Saturación",
            "question": "¿Se acumulan conexiones sin autenticación completa?",
            "why": (
                "Permite relacionar el tiempo de gracia con posible presión sobre el servicio SSH."
            ),
            "review": [
                "Número de conexiones preautenticadas.",
                "Errores de timeout.",
                "Coincidencia con degradación del servicio."
            ],
            "if_found": (
                "Si se acumulan conexiones, debe revisarse posible intento de saturación o DoS."
            ),
            "if_not_found": (
                "Si no hay acumulación, no hay evidencia de abuso por preautenticación."
            )
        }
    ],

    "LogLevel": [
        {
            "category": "Visibilidad",
            "question": "¿El nivel de registro permite reconstruir accesos y fallos SSH?",
            "why": (
                "Permite valorar si existe suficiente trazabilidad para investigar un incidente."
            ),
            "review": [
                "Detalle de eventos SSH.",
                "Accesos aceptados y fallidos.",
                "Eventos de desconexión o cambios relevantes."
            ],
            "if_found": (
                "Si el nivel de registro es insuficiente, debe aumentarse y reforzarse la retención de logs."
            ),
            "if_not_found": (
                "Si hay visibilidad suficiente, existe mejor capacidad de análisis posterior."
            )
        },
        {
            "category": "Huecos de evidencia",
            "question": "¿Faltan eventos esperados durante periodos de actividad?",
            "why": (
                "Permite detectar pérdida de visibilidad o configuración insuficiente de logging."
            ),
            "review": [
                "Periodos sin eventos.",
                "Rotación o eliminación de logs.",
                "Diferencias entre journalctl y archivos de log."
            ],
            "if_found": (
                "Si existen huecos, la investigación puede estar limitada y debe revisarse la causa."
            ),
            "if_not_found": (
                "Si no hay huecos relevantes, no se observan pérdidas claras de trazabilidad."
            )
        },
        {
            "category": "Correlación",
            "question": "¿Los logs permiten relacionar usuario, IP, hora y resultado de autenticación?",
            "why": (
                "Permite construir una línea temporal fiable de actividad SSH."
            ),
            "review": [
                "Usuario afectado.",
                "IP de origen.",
                "Fecha, hora y resultado del evento."
            ],
            "if_found": (
                "Si la correlación es posible, se puede avanzar en la reconstrucción del incidente."
            ),
            "if_not_found": (
                "Si no se puede correlacionar, debe documentarse como limitación forense."
            )
        }
    ],

    "GSSAPIAuthentication": [
        {
            "category": "Autenticación integrada",
            "question": "¿Existen intentos o accesos mediante GSSAPI/Kerberos?",
            "why": (
                "Permite comprobar si esta superficie de autenticación se está utilizando realmente."
            ),
            "review": [
                "Eventos GSSAPI en SSH.",
                "Tickets Kerberos presentes.",
                "Usuarios o principales implicados."
            ],
            "if_found": (
                "Si hay uso GSSAPI no esperado, debe investigarse el origen y la validez de los tickets."
            ),
            "if_not_found": (
                "Si no se utiliza Kerberos o no hay eventos GSSAPI, no hay evidencia directa de abuso."
            )
        },
        {
            "category": "Tickets",
            "question": "¿Hay tickets Kerberos inesperados o residuales en el sistema?",
            "why": (
                "Permite detectar abuso de material de autenticación alternativo."
            ),
            "review": [
                "Tickets en ubicaciones temporales.",
                "Propietario de los tickets.",
                "Fechas, dominios y principales asociados."
            ],
            "if_found": (
                "Si aparecen tickets sospechosos, debe investigarse posible robo o abuso de credenciales Kerberos."
            ),
            "if_not_found": (
                "Si no aparecen tickets sospechosos, no hay evidencia directa de abuso de GSSAPI."
            )
        },
        {
            "category": "Relaciones de confianza",
            "question": "¿Los dominios, realms o hosts confiables son los esperados?",
            "why": (
                "Permite identificar configuraciones Kerberos incorrectas o relaciones de confianza no justificadas."
            ),
            "review": [
                "Configuración de krb5.conf.",
                "Realms definidos.",
                "Hosts o dominios de origen."
            ],
            "if_found": (
                "Si hay relaciones no esperadas, debe revisarse la infraestructura de autenticación."
            ),
            "if_not_found": (
                "Si no hay relaciones anómalas, no se observan indicios claros de abuso por confianza Kerberos."
            )
        }
    ],

    "AllowUsersGroups": [
        {
            "category": "Control de acceso",
            "question": "¿Han intentado autenticarse cuentas que no deberían tener acceso SSH?",
            "why": (
                "Permite comprobar si la ausencia de restricciones amplía la superficie de ataque."
            ),
            "review": [
                "Usuarios objetivo en intentos fallidos.",
                "Cuentas de servicio o sistema.",
                "Cuentas sin necesidad de acceso remoto."
            ],
            "if_found": (
                "Si aparecen intentos contra cuentas no destinadas a SSH, debe restringirse el acceso."
            ),
            "if_not_found": (
                "Si no aparecen cuentas no esperadas, no hay evidencia directa de abuso."
            )
        },
        {
            "category": "Accesos aceptados",
            "question": "¿Alguna cuenta no autorizada ha iniciado sesión por SSH?",
            "why": (
                "Permite detectar explotación real de la ausencia de AllowUsers o AllowGroups."
            ),
            "review": [
                "Eventos de acceso aceptado por usuario.",
                "Propósito de la cuenta usada.",
                "Origen y horario del acceso."
            ],
            "if_found": (
                "Si una cuenta no autorizada inició sesión, debe investigarse como posible acceso indebido."
            ),
            "if_not_found": (
                "Si no hay accesos aceptados de cuentas no esperadas, no hay evidencia de explotación directa."
            )
        },
        {
            "category": "Superficie de ataque",
            "question": "¿Existen muchas cuentas locales con posibilidad de autenticación remota?",
            "why": (
                "Permite valorar el riesgo aunque no haya explotación confirmada."
            ),
            "review": [
                "Usuarios con shell interactiva.",
                "Cuentas antiguas o inactivas.",
                "Grupos con permiso de acceso remoto."
            ],
            "if_found": (
                "Si la superficie es amplia, se deben definir AllowUsers o AllowGroups y deshabilitar cuentas no usadas."
            ),
            "if_not_found": (
                "Si la superficie está limitada, el riesgo es menor, aunque conviene mantener restricciones explícitas."
            )
        }
    ],

    "Banner": [
        {
            "category": "Cumplimiento",
            "question": "¿Existe un banner legal o aviso de uso autorizado antes de la autenticación?",
            "why": (
                "Permite verificar si el sistema muestra una advertencia formal previa al acceso."
            ),
            "review": [
                "Directiva Banner en SSH.",
                "Archivo de banner configurado.",
                "Contenido mostrado al cliente antes de autenticarse."
            ],
            "if_found": (
                "Si existe banner, se refuerza la advertencia previa y la trazabilidad normativa."
            ),
            "if_not_found": (
                "Si no existe banner, no implica explotación técnica, pero sí una debilidad documental o de cumplimiento."
            )
        },
        {
            "category": "Contenido",
            "question": "¿El texto del banner indica uso autorizado y posible monitorización?",
            "why": (
                "Permite comprobar si el aviso cumple su función legal y disuasoria."
            ),
            "review": [
                "Claridad del mensaje.",
                "Referencia a uso autorizado.",
                "Referencia a monitorización o registro de actividad."
            ],
            "if_found": (
                "Si el contenido es adecuado, el sistema cumple mejor con requisitos de advertencia previa."
            ),
            "if_not_found": (
                "Si el contenido es ambiguo o incompleto, debe actualizarse."
            )
        },
        {
            "category": "Exposición de información",
            "question": "¿El banner revela datos sensibles del sistema u organización?",
            "why": (
                "Permite evitar que el banner ayude a un atacante en la fase de reconocimiento."
            ),
            "review": [
                "Versiones del sistema.",
                "Nombres internos, rutas o información de infraestructura.",
                "Datos organizativos innecesarios."
            ],
            "if_found": (
                "Si el banner revela información sensible, debe simplificarse y eliminar datos innecesarios."
            ),
            "if_not_found": (
                "Si no revela información sensible, no hay riesgo adicional de reconocimiento por esta vía."
            )
        }
    ],

    "Access_sshd_config": [
        {
            "category": "Integridad",
            "question": "¿El archivo sshd_config muestra modificaciones recientes o no justificadas?",
            "why": (
                "Permite detectar cambios que puedan haber habilitado acceso o reducido controles de seguridad."
            ),
            "review": [
                "Fecha de modificación del archivo.",
                "Usuario propietario y permisos.",
                "Relación temporal con actividad administrativa o sospechosa."
            ],
            "if_found": (
                "Si hay modificaciones no justificadas, debe investigarse quién realizó el cambio y qué directivas fueron alteradas."
            ),
            "if_not_found": (
                "Si no hay cambios sospechosos, no hay indicios claros de manipulación reciente."
            )
        },
        {
            "category": "Permisos",
            "question": "¿Los permisos permiten escritura por usuarios no autorizados?",
            "why": (
                "Permite determinar si un atacante podría alterar la configuración SSH."
            ),
            "review": [
                "Permisos efectivos del archivo.",
                "Propietario y grupo.",
                "Cambios recientes en permisos."
            ],
            "if_found": (
                "Si los permisos son demasiado permisivos, deben corregirse y revisarse cambios recientes."
            ),
            "if_not_found": (
                "Si los permisos son correctos, no hay evidencia de exposición por escritura indebida."
            )
        },
        {
            "category": "Configuración activa",
            "question": "¿La configuración modificada está cargada por el servicio SSH?",
            "why": (
                "Permite distinguir entre cambios presentes en archivo y cambios realmente activos."
            ),
            "review": [
                "Configuración efectiva del servicio.",
                "Fecha del último reinicio o recarga de SSH.",
                "Diferencias entre archivo y configuración activa."
            ],
            "if_found": (
                "Si cambios inseguros están activos, debe corregirse la configuración y recargar el servicio."
            ),
            "if_not_found": (
                "Si los cambios no están activos, el riesgo inmediato puede ser menor, pero debe limpiarse la configuración."
            )
        }
    ],

    "SSH_PrivateHostKey_Permissions": [
        {
            "category": "Permisos de claves",
            "question": "¿Las claves privadas del host SSH tienen permisos demasiado abiertos?",
            "why": (
                "Permite comprobar si material sensible del servidor puede ser leído por usuarios no autorizados."
            ),
            "review": [
                "Permisos de claves privadas del host.",
                "Propietario y grupo de los archivos.",
                "Acceso por usuarios no privilegiados."
            ],
            "if_found": (
                "Si los permisos son inseguros, deben corregirse y valorar rotación de claves si hubo exposición."
            ),
            "if_not_found": (
                "Si los permisos son restrictivos, no hay evidencia de exposición por permisos."
            )
        },
        {
            "category": "Acceso indebido",
            "question": "¿Hay indicios de lectura, copia o modificación de claves privadas SSH?",
            "why": (
                "Permite detectar posible robo de claves privadas del host."
            ),
            "review": [
                "Cambios de timestamp en claves privadas.",
                "Copias de claves en ubicaciones no esperadas.",
                "Actividad de usuarios sobre directorios de claves."
            ],
            "if_found": (
                "Si hay indicios de acceso indebido, deben rotarse las claves y revisar confianza de clientes."
            ),
            "if_not_found": (
                "Si no hay indicios de copia o lectura indebida, no hay evidencia directa de robo de claves."
            )
        },
        {
            "category": "Suplantación",
            "question": "¿Existen alertas o cambios de identidad SSH del servidor?",
            "why": (
                "Permite valorar riesgo de suplantación del servidor o ataque Man-in-the-Middle."
            ),
            "review": [
                "Cambios recientes en claves de host.",
                "Mensajes de host key changed en clientes.",
                "Rotaciones no documentadas de claves SSH."
            ],
            "if_found": (
                "Si hay cambios no justificados de identidad SSH, debe investigarse posible suplantación."
            ),
            "if_not_found": (
                "Si no hay alertas de identidad, no se observan indicios de suplantación de host."
            )
        }
    ],

    "DisableForwarding": [
        {
            "category": "Forwarding efectivo",
            "question": "¿El forwarding está realmente habilitado en la configuración efectiva?",
            "why": (
                "Permite comprobar si el hallazgo representa una exposición activa."
            ),
            "review": [
                "Valor efectivo de AllowTcpForwarding o DisableForwarding.",
                "Diferencia entre archivo y configuración activa.",
                "Estado del servicio tras reinicio o recarga."
            ],
            "if_found": (
                "Si el forwarding está habilitado, debe restringirse según la política de seguridad."
            ),
            "if_not_found": (
                "Si no está activo, puede tratarse de una configuración no cargada o hallazgo a revisar."
            )
        },
        {
            "category": "Uso de túneles",
            "question": "¿Existen sesiones con túneles locales, remotos o dinámicos?",
            "why": (
                "Permite detectar abuso operativo de la capacidad de forwarding."
            ),
            "review": [
                "Conexiones persistentes.",
                "Puertos abiertos por procesos SSH.",
                "Sesiones SSH largas o no justificadas."
            ],
            "if_found": (
                "Si hay túneles activos, debe investigarse posible pivoting o canal encubierto."
            ),
            "if_not_found": (
                "Si no hay túneles activos, no hay evidencia actual de abuso."
            )
        },
        {
            "category": "Acceso interno",
            "question": "¿El forwarding permitió acceder a servicios internos no expuestos directamente?",
            "why": (
                "Permite valorar el impacto real de la mala configuración."
            ),
            "review": [
                "Conexiones hacia localhost o redes internas.",
                "Puertos internos accedidos.",
                "Relación entre usuario SSH y acceso a servicios privados."
            ],
            "if_found": (
                "Si hay acceso interno mediante forwarding, debe analizarse el alcance y las credenciales usadas."
            ),
            "if_not_found": (
                "Si no hay acceso interno observado, no hay evidencia directa de explotación mediante forwarding."
            )
        }
    ]
}

# ============================================================================
# 8) FUNCIÓN PRINCIPAL — ENRIQUECER HALLAZGO
# ============================================================================

def enrich_hallazgo(hallazgo):
    """
    Recibe un hallazgo de findings.json y lo convierte en un
    hallazgo ampliado para el Playbook.
    """
    title = hallazgo.get("title")

    default_forensic = {
        "logs": [],
        "files": [],
        "commands": [],
        "indicators": [],
        "notes": ""
    }

    forensic_data = default_forensic.copy()
    forensic_data.update(FORENSIC.get(title, {}))

    checklist_specific = CHECKLIST_BY_FINDING.get(title, [])

    enriched = hallazgo.copy()
    enriched["mitre"] = MITRE_MAP.get(title, [])
    enriched["killchain"] = KILLCHAIN_MAP.get(title, [])
    enriched["explanation_ext"] = EXPLANATION_TEXT.get(title, "")
    enriched["exploitation"] = EXPLOITATION.get(title, "")
    enriched["forensic"] = forensic_data

    # Nuevo modelo de checklist
    enriched["checklist_common"] = CHECKLIST_COMMON
    enriched["checklist_specific"] = checklist_specific

    # Compatibilidad con plantillas antiguas, por si queda alguna usando h.checklist
    enriched["checklist"] = [
        item.get("question", "") for item in CHECKLIST_COMMON
    ] + [
        item.get("question", "") for item in checklist_specific
    ]

    return enriched
