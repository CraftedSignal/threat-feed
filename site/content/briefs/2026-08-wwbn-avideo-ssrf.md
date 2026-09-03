---
title: WWBN AVideo SSRF Filter Bypass via NAT64 Hex Encoding
slug: 2026-08-wwbn-avideo-ssrf
description: WWBN AVideo is vulnerable to a Server-Side Request Forgery (SSRF) bypass in the isSSRFSafeURL function due to improper normalization of hex-encoded NAT64 addresses.
date: "2026-08-30T17:11:37Z"
lastmod: "2026-09-03T13:21:05Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wwbn:avideo:*:*:*:*:*:*:*:*
tags:
  - credential-access
  - web-application
  - authentication-bypass
  - web-application-vulnerability
  - path-traversal
  - reconnaissance
  - web-vulnerability
  - csrf
  - session-management
vendors:
  - WWBN
products:
  - AVideo
  - AVideo (e01e41ecc and earlier)
  - AVideo (<= e01e41ecc)
  - AVideo (<= 9c39d8c8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can bypass SSRF protections by supplying hex-encoded NAT64 addresses like 64:ff9b::a9fe:a9fe to reach cloud metadata services and loopback interfaces.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
    evidence: An unauthenticated attacker can therefore submit unlimited login attempts, enabling unrestricted password-guessing attacks.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: 'An attacker who submits valid credentials and sets User-Agent: AVideoEncoder bypasses two-factor authentication.'
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: The vulnerability allows attackers to use expired tokens to reset account passwords indefinitely.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Attackers who obtain a recovery token can use it at any time to change the target account's password and gain full account access.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Attackers can exploit this to destroy audit logs
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: the vulnerability enabling both file deletion and information disclosure about the filesystem
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: Attackers who obtain a video_id_hash can replay it indefinitely to authenticate as the video owner with full privileges, and the credential remains valid even after the owner changes their password.
    confidence_band: high
cves:
  - id: CVE-2026-82648
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82648
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82644
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84479
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84480
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84476
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84478
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84482
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85154
rules:
  - title: Detect CVE-2026-82644 Exploitation - Brute Force Bypass via User-Agent Manipulation
    description: Detects potential brute-force attempts on login endpoints by identifying high-frequency POST requests with missing or common bot User-Agent strings, which characterize the CVE-2026-82644 bypass vector.
    platform: sigma
    severity: high
    tactics:
      - credential_access
    techniques:
      - T1110.001
    data_sources:
      - webserver
  - title: Detect Exploitation of CVE-2026-84479 - Suspicious User-Agent Usage in AVideo
    description: Detects potential exploitation of CVE-2026-84479 where an attacker spoofs the User-Agent to bypass AVideo security controls.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - initial_access
    techniques:
      - T1550.002
    data_sources:
      - webserver
  - title: Detect CVE-2026-84478 Exploitation - Path Traversal in AVideo API
    description: Detects exploitation attempts against the WWBN AVideo get_api_login_code endpoint using path traversal sequences in the code parameter
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1083
      - T1190
    data_sources:
      - webserver
rules_count: 3
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review server access logs for requests containing hex-encoded IPv6 addresses targeting internal metadata endpoints
      owner: SOC
      due: 24h
      evidence: CVE-2026-82648 exploitation vector involves NAT64 hex-encoded addresses
  mitigation_plan:
    - priority: immediate
      action: Patch AVideo to the latest version as recommended by WWBN
      owner: IT Operations
      addresses: CVE-2026-82648
      evidence: Source confirms vulnerability in AVideo isSSRFSafeURL function
updates:
  - at: "2026-09-02T01:10:23Z"
    level: L2
    summary: added coverage for AVideo
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84480
  - at: "2026-09-02T01:10:49Z"
    level: L2
    summary: added coverage for AVideo
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84476
  - at: "2026-09-02T01:10:59Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-84478 Exploitation - Path Traversal in AVideo API'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84478
  - at: "2026-09-02T01:11:05Z"
    level: L2
    summary: added coverage for AVideo (<= 9c39d8c8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-84482
  - at: "2026-09-03T13:21:05Z"
    level: L2
    summary: added coverage for AVideo
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-85154
---

WWBN AVideo contains a server-side request forgery (SSRF) vulnerability identified as CVE-2026-82648, located within the isSSRFSafeURL function. The vulnerability stems from a failure to correctly normalize NAT64 addresses when they are presented in a hexadecimal format. Because the function does not account for these specific representations, attackers can bypass existing URL filtering protections. By crafting malicious requests containing NAT64 addresses such as 64:ff9b::a9fe:a9fe, an unauthorized actor can force the application to perform requests against restricted internal resources, including cloud metadata services (e.g., 169.254.169.254) and local loopback interfaces. This flaw is particularly significant in cloud-hosted environments where metadata services store sensitive IAM credentials or instance configuration details. Successful exploitation allows an attacker to interact with internal network segments that are otherwise protected from external reach, potentially resulting in credential theft or further lateral movement within the hosting infrastructure.

## Impact

Successful exploitation allows unauthenticated attackers to bypass SSRF protections, enabling unauthorized interaction with internal cloud metadata services and local network resources. This can result in the exfiltration of instance-level credentials, sensitive configuration data, or internal system exploitation, compromising the confidentiality and integrity of the AVideo server instance.

## Recommendation

- Audit web application logs for HTTP requests containing unusual IPv6 NAT64 or hex-encoded address strings directed at internal hostnames or IP ranges.
- Implement a secondary validation layer at the network edge or application-level proxy to verify that requests originating from AVideo are not destined for reserved or private IP ranges, regardless of the encoding used in the URL.
- Monitor for unauthorized access attempts to local cloud metadata services from the AVideo application host.
- Review all AVideo instance configurations to ensure they are updated to the latest vendor-provided patches that resolve CVE-2026-82648.
