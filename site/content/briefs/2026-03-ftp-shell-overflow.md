---
title: FTP Shell Server 6.83 Buffer Overflow Vulnerability (CVE-2019-25619)
slug: 2026-03-ftp-shell-overflow
description: FTP Shell Server 6.83 contains a buffer overflow vulnerability (CVE-2019-25619) in the 'Account name to ban' field, enabling a local attacker to execute arbitrary code by injecting shellcode through a crafted string in the Manage FTP Accounts dialog.
date: "2026-03-23T14:00:00Z"
severities:
  - high
type: advisory
types:
  - advisory
tags:
  - buffer-overflow
  - code-execution
  - ftp
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2019-25619
  - http://www.ftpshell.com/index.htm
  - https://www.exploit-db.com/exploits/46685
  - https://www.vulncheck.com/advisories/ftp-shell-server-buffer-overflow-via-account-name
rules:
  - title: Detect FTP Shell Server Calc.exe Execution
    description: Detects the execution of calc.exe spawned by ftpshell.exe, indicating potential exploitation of CVE-2019-25619.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect FTP Shell Server Suspicious Process
    description: Detects the execution of command interpreter spawned by ftpshell.exe, indicating potential exploitation.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

FTP Shell Server version 6.83 is vulnerable to a buffer overflow (CVE-2019-25619). This vulnerability exists within the 'Account name to ban' field, located in the Manage FTP Accounts dialog. A local attacker can exploit this flaw by providing a specially crafted string as the account name. This crafted string allows for shellcode injection, enabling the attacker to overwrite the return address within the application's memory. Successful exploitation allows an attacker to execute arbitrary…
