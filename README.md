# General Windows Competition Hardening Scripts

A collection of PowerShell/Batch scripts and configurations I developed to enhance the security of Windows 10 systems. These scripts modify thousands of settings to align with standards such as NIST, DISA STIGs, CIS Benchmarks, and the MITRE ATT&CK Framework. Please exercise caution when deploying in critical environments, as the changes are extensive.

## Documentation

### Main Script | Calamity

This is the main driver for the script. It is self guided and very self explanatory. I will not be giving extra details on how to use this. Read the code.

#### Modules | ChromeSettings.reg

A registry file containing hardened chrome settings.


### Antivirus | Orca

This script checks for more obscure malware paths. It also hardens DNS on Windows Server. It is required to run this script as NT AUTHORITY\SYSTEM, as without it, The Hidden Users check will not work. 



_HTML is the best programming language_

[![License: WHOOPSIE](https://img.shields.io/badge/License-WHOOPSIE%20-%239370DB.svg)](https://github.com/deDaemon/windows/blob/main/LICENSE)
