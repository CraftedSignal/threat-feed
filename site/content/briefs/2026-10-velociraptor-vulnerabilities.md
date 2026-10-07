---
title: Multiple Vulnerabilities in Rapid7 Velociraptor
slug: 2026-10-velociraptor-vulnerabilities
description: Rapid7 Velociraptor is affected by multiple vulnerabilities allowing a remote, authenticated attacker to manipulate files, bypass security controls, escalate privileges, and exfiltrate sensitive data.
date: "2026-10-06T00:41:35Z"
lastmod: "2026-10-07T00:42:12Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:rapid7:velociraptor:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rapid7
  - velociraptor
vendors:
  - Rapid7
products:
  - Velociraptor
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1547
    technique_name: Boot or Logon Autostart Execution
    evidence: The identified vulnerabilities allow for file manipulation and privilege escalation, which could be leveraged to establish persistence.
    confidence_band: med
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The advisory states the vulnerabilities permit an authenticated attacker to gain extended privileges.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: The advisory notes the ability to disclose confidential information, potentially including sensitive data collected from endpoints.
    confidence_band: high
cves:
  - id: CVE-2026-78411
    cvss: 6.5
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3731
  - https://cyber.gc.ca/en/alerts-advisories/rapid7-security-advisory-av26-1004
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Review and harden access controls to Velociraptor management interfaces.
      owner: IT Operations
      due: 24h
      evidence: Advisory notes the attacker must be authenticated to exploit these vulnerabilities.
  mitigation_plan:
    - priority: immediate
      action: Check vendor support portal for patches and upgrade Velociraptor to the latest version.
      owner: IT Operations
      addresses: Velociraptor
      evidence: General remediation for reported product vulnerabilities.
updates:
  - at: "2026-10-07T00:42:12Z"
    level: L2
    summary: added CVE-2026-78411
    sources:
      - cccs
    source_urls:
      - https://cyber.gc.ca/en/alerts-advisories/rapid7-security-advisory-av26-1004
---

Rapid7 Velociraptor is affected by a set of vulnerabilities that permit a remote, authenticated attacker to perform unauthorized actions within the platform. The impact of these flaws includes the ability to modify arbitrary files on the system, bypass existing security restrictions, escalate privileges to gain full administrative control, and disclose sensitive information. Because Velociraptor is designed for endpoint visibility and response, these vulnerabilities are particularly critical, as they allow an attacker to subvert the very tools intended for security monitoring. Organizations using Velociraptor should prioritize restricting access to the server components to authorized personnel only and audit all administrative sessions for anomalous behavior.

## Impact

Successful exploitation could allow an attacker to compromise the integrity of the security monitoring infrastructure, potentially leading to the complete takeover of the Velociraptor server. This could facilitate the deployment of secondary malware, the exfiltration of collected forensic data from endpoints across the environment, or the disabling of security logging on the managed systems.

## Recommendation

Prioritized, concrete actions for security operations and IT teams:

- Restrict access to the Velociraptor web console and API endpoints to trusted management IP ranges only via network-level firewalls.
- Implement strict multi-factor authentication (MFA) for all accounts with administrative privileges on the Velociraptor server.
- Monitor server-side logs for unexpected configuration changes or the execution of administrative functions by non-standard user accounts.
- Regularly audit the Velociraptor event logs for unusual file-access patterns that deviate from standard forensic collection workflows.
