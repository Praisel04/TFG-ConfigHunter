1. sudo python3 main.py scan ssh

GENERACION DE PLAYBOOKS

main.py llama a generate_playbook_report.py

generate_playbook llama a playbook_engine

Desde playnokk engine, se enriquecen los hallazgos con las tecnicas mittre y fases de cyber definidas para cada uno

Despues se genera el reporte.


--------------------------------------------------------------------------------------------------------------------
DETALLE DE LA ESTRUCTURA DE LOS PLAYBOOKS

1. TITULO DEL HALLAZGO
2. Descipción ampliada - Campo EXPLANATION_TEXT ---> playbook_engine
3. Importancia Defensiva - Campo explanation ---> ssh_check
4. Explotación del hallazgo - Campo EXPLOITATION ---> playbook_engine
5. MITRE ATT&CK - Campo MITRE_MAP ---> playbook_engine
6. Cyber Kill Chain - Campo KILLCHAIN_MAP ---> playbook_engine 
7. Indicadores DFIR - Campo FORENSIC ---> playbook_engine
8. Checklist Forense - Campo CHECKLIST ---> playbook_engine





