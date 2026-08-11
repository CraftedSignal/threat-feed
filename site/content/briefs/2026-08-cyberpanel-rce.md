---
title: Authenticated Remote Code Execution in CyberPanel
slug: 2026-08-cyberpanel-rce
description: CyberPanel version 2.4.3 contains an authenticated remote code execution vulnerability in its remote backup feature that allows an attacker to inject an SSH public key into the root user's authorized_keys file.
date: "2026-08-10T21:37:02Z"
lastmod: "2026-08-11T11:35:37Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - CyberPanel
products:
  - CyberPanel (2.4.3)
  - CyberPanel (<= 2.4.3)
  - CyberPanel
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: Attackers can exploit the unverified SSH public key retrieval process to write an attacker-controlled public key directly to /root/.ssh/authorized_keys, granting persistent root access to the host system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: CyberPanel 2.4.3... contains an authenticated remote code execution vulnerability in the remote backup feature that allows authenticated attackers to gain root-level SSH access.
    confidence_band: high
cves:
  - id: CVE-2026-71965
    cvss: 8.8
  - id: CVE-2026-71966
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71965
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71966
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2743
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CyberPanel to address CVE-2026-71965
      owner: IT Operations
      due: 48h
      evidence: Source states vulnerability is fixed in commit eca0c3c
  mitigation_plan:
    - priority: immediate
      action: Restrict access to CyberPanel management interface
      owner: IT Operations
      addresses: CVE-2026-71965
      evidence: Vulnerability requires authentication to exploit
updates:
  - at: "2026-08-10T21:37:05Z"
    level: L2
    summary: added CVE-2026-71966
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-71966
  - at: "2026-08-11T11:35:37Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2743
---

CyberPanel version 2.4.3 is vulnerable to an authenticated remote code execution flaw within its remote backup management functionality. The vulnerability arises from an insecure implementation of SSH public key retrieval, where the application fails to validate the source of remote server configurations. An authenticated attacker can supply a malicious remote server address to the backup service, which then retrieves an attacker-controlled public key and writes it directly to the '/root/.ssh/authorized_keys' file. This provides the attacker with persistent root-level SSH access to the underlying host system. This vulnerability was addressed in commit eca0c3c. Defenders should prioritize auditing CyberPanel configurations and ensuring updates to versions beyond 2.4.3 are applied to mitigate the risk of unauthorized persistence.

## Attack Chain

1. The attacker authenticates to the CyberPanel management interface using compromised or registered credentials.
2. The attacker navigates to the remote backup configuration settings.
3. The attacker provides a malicious remote server address in the backup target field.
4. The application initiates an SSH connection to the attacker-controlled server to retrieve backup configuration files.
5. The attacker's server delivers a payload containing a public SSH key disguised as part of the backup process.
6. The CyberPanel application process, running with elevated privileges, writes the received public key to the '/root/.ssh/authorized_keys' file.
7. The attacker establishes an SSH session to the host system using the corresponding private key.
8. The attacker obtains full, persistent root access to the server.

## Impact

Successful exploitation of this vulnerability grants an attacker full root-level persistence on the CyberPanel host. This facilitates complete system compromise, including the potential for data exfiltration, service disruption, and lateral movement within the hosting infrastructure.

## Recommendation

* Update CyberPanel to a version containing the fix for CVE-2026-71965 (commit eca0c3c).
* Monitor file access events for changes to the '/root/.ssh/authorized_keys' file on servers running CyberPanel.
* Restrict administrative access to the CyberPanel interface to trusted IP ranges to prevent unauthorized authentication.
* Implement host-based monitoring to detect unexpected SSH key injections in critical system directories.
