---
brief_id: brief-2026-08-cyberpanel-rce
event_id: brief-2026-08-cyberpanel-rce
revision: 2
activity_at: "2026-11-21T19:10:12Z"
revision_history:
  - revision: 2
    at: "2026-11-21T19:10:12Z"
    checksum: sha256:a203251f86c8f1d9c397f7655ec1b9b0d8f904d103fd685fa8e422ed9941d979
    summary: poc_available
    changed_fields:
      - affected_products
      - cpes
      - cve_verification
      - cves
      - has_poc
      - lastmod
      - poc_references
      - priority
      - priority_score
      - priority_signals
      - references
      - ttps
      - updates
    source_urls:
      - https://sploitus.com/exploit?id=6D7C380E-369C-5E3C-A134-6C27BBE3754D&utm_source=rss&utm_medium=rss
title: Authenticated Remote Code Execution in CyberPanel
slug: 2026-08-cyberpanel-rce
description: CyberPanel version 2.4.3 contains an authenticated remote code execution vulnerability in its remote backup feature that allows an attacker to inject an SSH public key into the root user's authorized_keys file.
date: "2026-08-10T21:37:02Z"
lastmod: "2026-11-21T19:05:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source corroborated by NVD
cpes:
  - cpe:2.3:a:cyberpanel:cyberpanel:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=6D7C380E-369C-5E3C-A134-6C27BBE3754D&utm_source=rss&utm_medium=rss
vendors:
  - CyberPanel
products:
  - CyberPanel
product_versions:
  - product: CyberPanel
    range: 2.4.3
  - product: CyberPanel
    range: < 3.0.0
  - product: CyberPanel
    range: <= 2.4.3
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    subtechnique_id: T1098.004
    subtechnique_name: SSH Authorized Keys
    evidence: Attackers can exploit the unverified SSH public key retrieval process to write an attacker-controlled public key directly to /root/.ssh/authorized_keys, granting persistent root access to the host system.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1133
    technique_name: External Remote Services
    evidence: CyberPanel 2.4.3... contains an authenticated remote code execution vulnerability in the remote backup feature that allows authenticated attackers to gain root-level SSH access.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CyberPanel before 3.0.0 contains a hard-coded JWT secret vulnerability in the WebTerminal FastAPI SSH service that allows unauthenticated remote attackers to forge valid authentication tokens.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can... authenticate to the terminal service without any valid credentials and receive a root shell.
    confidence_band: high
cve_verification:
  CVE-2026-67614:
    status: verified
    source: nvd
    checked_at: 2026-11-21T19:05:04.305203958Z
  CVE-2026-71965:
    status: verified
    source: nvd
    checked_at: 2026-11-21T19:05:05.450665587Z
  CVE-2026-71966:
    status: verified
    source: nvd
    checked_at: 2026-11-21T19:05:06.149758754Z
cves:
  - id: CVE-2026-71965
    cvss: 8.8
    epss: 0.0044
    kev_status: "false"
  - id: CVE-2026-71966
    cvss: 8.8
    epss: 0.03276
    kev_status: "false"
  - id: CVE-2026-67614
    cvss: 9.8
    epss: 0.00964
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71965
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71966
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2743
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67614
  - https://www.vulncheck.com/advisories/cyberpanel-hard-coded-jwt-secret-authentication-bypass-via-webterminal
  - https://github.com/usmannasir/cyberpanel/issues/1858
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2831
  - https://sploitus.com/exploit?id=6D7C380E-369C-5E3C-A134-6C27BBE3754D&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CyberPanel WebTerminal Authentication Attempts
    description: Detects external network connections to the CyberPanel WebTerminal service on port 8888 which may indicate attempted exploitation of CVE-2026-67614.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
rules_count: 1
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
  - at: "2026-08-13T18:56:20Z"
    level: L2
    summary: 'added detection rule: Detect CyberPanel WebTerminal Authentication Attempts'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-67614
  - at: "2026-08-14T14:08:26Z"
    level: L2
    summary: added CVE-2026-67614
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-2831
  - at: "2026-11-21T19:05:06Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=6D7C380E-369C-5E3C-A134-6C27BBE3754D&utm_source=rss&utm_medium=rss
---

## Overview

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
