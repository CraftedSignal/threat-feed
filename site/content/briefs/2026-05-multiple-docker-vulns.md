---
title: Multiple Vulnerabilities in Docker Desktop Allow Remote Code Execution
slug: 2026-05-multiple-docker-vulns
description: Multiple vulnerabilities in Docker Desktop versions prior to 4.71.0 allow a remote attacker to execute arbitrary code.
date: "2026-05-20T14:08:12Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - vulnerability
  - rce
  - docker
vendors:
  - Docker
products:
  - Docker Desktop
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1569
    technique_name: System Services
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0620/
  - https://docs.docker.com/security/security-announcements/#docker-desktop-4680-security-update-cve-2026-5817
  - https://docs.docker.com/security/security-announcements/#docker-desktop-4710-security-update-cve-2026-5843
  - https://www.cve.org/CVERecord?id=CVE-2026-5817
  - https://www.cve.org/CVERecord?id=CVE-2026-5843
rules:
  - title: Detect CVE-2026-5817 and CVE-2026-5843 Exploitation — Suspicious Docker Desktop Process Creation
    description: Detects CVE-2026-5817 and CVE-2026-5843 exploitation — Monitors for the creation of suspicious processes by Docker Desktop, indicative of remote code execution.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.001
    data_sources:
      - process_creation
      - windows
  - title: Detect CVE-2026-5817 and CVE-2026-5843 Exploitation — Docker Desktop Network Connection to External IP
    description: Detects CVE-2026-5817 and CVE-2026-5843 exploitation — Monitors for Docker Desktop making network connections to external IP addresses after suspicious activity.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1071.001
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Multiple vulnerabilities have been discovered in Docker Desktop versions prior to 4.71.0. These vulnerabilities can be exploited by an attacker to achieve remote code execution. The vulnerabilities are tracked as CVE-2026-5817 and CVE-2026-5843. Docker released security updates on April 7, 2026, and April 27, 2026, to address these issues. Exploitation of these vulnerabilities could allow an attacker to gain control of the affected system, potentially leading to data breaches, system compromise, or other malicious activities. Defenders should ensure Docker Desktop is updated to a version that includes the patches.

## Attack Chain

1.  Attacker identifies a vulnerable Docker Desktop instance running a version prior to 4.71.0.
2.  Attacker crafts a malicious request targeting one of the vulnerabilities (CVE-2026-5817 or CVE-2026-5843). The exact nature of the request depends on the specific vulnerability.
3.  The malicious request is sent to the vulnerable Docker Desktop instance.
4.  Docker Desktop processes the request, triggering the vulnerability.
5.  The vulnerability allows the attacker to execute arbitrary code within the context of the Docker Desktop application.
6.  The attacker leverages the code execution to gain further access to the host system, potentially escalating privileges.
7.  The attacker may install malware, exfiltrate sensitive data, or perform other malicious activities.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code on the affected system. This could lead to complete system compromise, data breaches, or the deployment of ransomware. Given the widespread use of Docker Desktop in development environments, a successful attack could impact numerous developers and organizations.

## Recommendation

*   Upgrade Docker Desktop to version 4.71.0 or later to remediate CVE-2026-5817 and CVE-2026-5843.
*   Monitor network traffic for suspicious activity related to Docker Desktop processes using network connection logs to detect potential exploitation attempts.
*   Implement the Sigma rule provided to detect suspicious process creation events indicative of successful exploitation.
