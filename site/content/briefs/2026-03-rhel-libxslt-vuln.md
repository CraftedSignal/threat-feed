---
title: Red Hat Enterprise Linux libxslt Vulnerability Allows Code Execution or File Manipulation
slug: 2026-03-rhel-libxslt-vuln
description: A local attacker can exploit a vulnerability in libxslt in Red Hat Enterprise Linux to execute arbitrary program code or manipulate files.
date: "2026-03-24T10:16:03Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - libxslt
  - rhel
  - code-execution
  - file-manipulation
  - linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2025-0626
rules:
  - title: Detect Suspicious Libxslt Process Execution
    description: Detects suspicious process execution involving libxslt, potentially indicating exploitation attempts.
    platform: sigma
    severity: high
    tactics:
      - execution
      - privilege_escalation
    data_sources:
      - process_creation
      - linux
  - title: Detect Malicious File Modification via Libxslt
    description: Detects file modifications by processes related to libxslt that may indicate malicious activity.
    platform: sigma
    severity: critical
    tactics:
      - persistence
      - privilege_escalation
    data_sources:
      - file_event
      - linux
rules_count: 2
---

A vulnerability exists within the libxslt library in Red Hat Enterprise Linux (RHEL) that could be exploited by a local attacker. While specific details regarding the vulnerability (CVE number, affected versions) are not provided in this advisory, the potential impact includes arbitrary code execution or manipulation of files on the affected system. Due to the lack of specific details, the scope of targeting remains unknown, but any RHEL system utilizing libxslt is potentially vulnerable. It is imperative that detection engineers address this threat by implementing proactive measures to identify and mitigate potential exploitation attempts, particularly focusing on detecting unexpected behavior associated with libxslt processes.

## Attack Chain

1.  The attacker gains local access to a Red Hat Enterprise Linux system. This could be achieved through various means, such as compromising a user account or exploiting a separate vulnerability to gain initial access.
2.  The attacker crafts a malicious XSLT stylesheet specifically designed to exploit the libxslt vulnerability. This stylesheet could contain code intended for execution or file manipulation.
3.  The attacker utilizes a program or script that leverages libxslt to process the crafted malicious stylesheet. This could involve using command-line tools or applications that rely on libxslt for XML transformations.
4.  During the processing of the malicious stylesheet, the libxslt vulnerability is triggered, leading to the execution of arbitrary code within the context of the application using libxslt.
5.  The attacker leverages the code execution to escalate privileges on the system, potentially gaining root access.
6.  Alternatively, the attacker uses the vulnerability to manipulate files on the system, modifying configurations, injecting malicious code into existing files, or exfiltrating sensitive data.
7.  The attacker maintains persistence on the compromised system, ensuring continued access and control.
8.  The attacker achieves their objective, which could be data theft, system disruption, or further lateral movement within the network.

## Impact

Successful exploitation of this vulnerability could allow a local attacker to gain complete control over the affected Red Hat Enterprise Linux system. This may lead to data breaches, system outages, or the installation of backdoors for persistent access. Given the widespread use of RHEL in enterprise environments, a successful attack could have significant consequences across various sectors. The potential for arbitrary code execution and file manipulation makes this a high-severity vulnerability.

## Recommendation

*   Monitor process execution for unexpected or unusual activity involving libxslt binaries using the provided Sigma rule `Detect Suspicious Libxslt Process Execution`.
*   Implement file integrity monitoring to detect unauthorized modifications to critical system files using the Sigma rule `Detect Malicious File Modification via Libxslt`.
*   Regularly audit user privileges and access controls to minimize the potential impact of a successful exploit.
*   Investigate and remediate any identified instances of potentially malicious XSLT stylesheets being processed on RHEL systems.
