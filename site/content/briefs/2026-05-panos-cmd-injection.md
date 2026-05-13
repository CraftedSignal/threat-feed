---
title: CVE-2026-0261 PAN-OS Authenticated Admin Command Injection Vulnerability
slug: 2026-05-panos-cmd-injection
description: CVE-2026-0261 describes multiple command injection vulnerabilities in Palo Alto Networks PAN-OS software that allow an authenticated administrator to bypass system restrictions and execute arbitrary commands as root.
date: "2026-05-13T16:06:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve
  - command injection
  - palo alto networks
vendors:
  - Palo Alto Networks
products:
  - PAN-OS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
references:
  - https://security.paloaltonetworks.com/CVE-2026-0261
  - https://live.paloaltonetworks.com/t5/community-blogs/tips-amp-tricks-how-to-secure-the-management-access-of-your-palo/ba-p/464431
  - https://docs.paloaltonetworks.com/best-practices/10-1/administrative-access-best-practices/administrative-access-best-practices/deploy-administrative-access-best-practices
rules:
  - title: Detect CVE-2026-0261 Exploitation Attempt - PAN-OS WebUI Command Injection
    description: Detects CVE-2026-0261 exploitation attempt via suspicious characters in the PAN-OS WebUI, indicating potential command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - webserver
  - title: Detect CVE-2026-0261 Exploitation Attempt - PAN-OS CLI Command Injection
    description: Detects CVE-2026-0261 exploitation attempt via suspicious characters in the PAN-OS CLI input, indicating potential command injection.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059.004
      - T1190
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

Multiple command injection vulnerabilities exist in Palo Alto Networks PAN-OS software, potentially enabling an authenticated administrator to bypass system restrictions and execute arbitrary commands as a root user (CVE-2026-0261). Exploitation requires access to the PAN-OS CLI or Web UI. The vulnerabilities affect PA-Series, VM-Series firewalls, and Panorama (virtual and M-Series) running vulnerable PAN-OS versions. Cloud NGFW and Prisma Access are not affected. Patches are scheduled to be released by May 28, 2026. This vulnerability could allow an attacker with administrative access to gain complete control of the affected system, potentially leading to data breaches, system compromise, or denial of service.

## Attack Chain

1. An attacker gains administrative access to the PAN-OS CLI or Web UI. This could be through stolen credentials, social engineering, or other means.
2. The attacker identifies an input field or command within the PAN-OS CLI or Web UI that is vulnerable to command injection.
3. The attacker crafts a malicious input string containing shell metacharacters and a command to be executed.
4. The attacker submits the malicious input through the vulnerable field or command.
5. The PAN-OS software improperly neutralizes the special elements within the input string.
6. The PAN-OS software executes the attacker-controlled command as the root user.
7. The attacker leverages the root privileges to install malware, modify system configurations, or exfiltrate sensitive data.

## Impact

Successful exploitation of CVE-2026-0261 could allow an attacker with administrative privileges to execute arbitrary commands as root on the affected PAN-OS device. This could lead to complete system compromise, data breaches, or denial of service. The severity of the impact is concentrated on the affected device, with high confidentiality, integrity, and availability risks. Palo Alto Networks is not aware of any malicious exploitation of these issues.

## Recommendation

*   Upgrade to the fixed versions of PAN-OS as specified in the Palo Alto Networks advisory for CVE-2026-0261. Specifically, upgrade PAN-OS 12.1 to >= 12.1.4-h5 or >= 12.1.7, PAN-OS 11.2 to >= 11.2.4-h17, >= 11.2.7-h13, >= 11.2.10-h6 or >= 11.2.12, PAN-OS 11.1 to >= 11.1.4-h33, >= 11.1.6-h32, >= 11.1.7-h6, >= 11.1.10-h25, >= 11.1.13-h5 or >= 11.1.15 and PAN-OS 10.2 to >= 10.2.7-h34, >= 10.2.10-h36, >= 10.2.13-h21, >= 10.2.16-h7 or >= 10.2.18-h6.
*   Restrict CLI access to a limited group of administrators as recommended in the Palo Alto Networks advisory and documentation.
*   Restrict access to the management web interface to only trusted internal IP addresses to mitigate the risk as per Palo Alto Networks' best practice deployment guidelines, as described in the linked LIVEcommunity article and technical documentation.
*   Enable Threat IDs 510017, 510018 and 510024 to block attacks and Threat IDs 510021, 510025 and 510026 to detect attacks from Applications and Threats content version 9100-10044 and later.
