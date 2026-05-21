---
title: Actively Exploited Vulnerabilities in Sparx Pro Cloud Server and Enterprise Architect
slug: 2026-05-sparx-rce
description: Multiple vulnerabilities, including a critical authentication bypass (CVE-2026-42097), affect Sparx Systems Pro Cloud Server and Enterprise Architect, potentially leading to remote code execution and data compromise; active exploitation is likely given available PoCs.
date: "2026-05-21T10:09:54Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
tags:
  - vulnerability
  - rce
  - authentication-bypass
  - sqli
vendors:
  - Sparx Systems
products:
  - Pro Cloud Server
  - Enterprise Architect
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
cves:
  - id: CVE-2026-42097
    epss: 0.0009
  - id: CVE-2026-42098
    epss: 0.00039
  - id: CVE-2026-42096
    epss: 0.00039
  - id: CVE-2026-42099
    epss: 0.00225
  - id: CVE-2026-42100
    epss: 0.00042
references:
  - https://ccb.belgium.be/advisories/warning-actively-exploited-critical-and-multiple-high-vulnerabilities-sparx-pro-cloud
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42096
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42097
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42098
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42099
  - https://nvd.nist.gov/vuln/detail/CVE-2026-42100
  - https://sploit.tech/2026/05/19/Sparx-Enterprise-Architect-PCS.html
  - https://cert.pl/en/posts/2026/05/CVE-2026-42096
  - https://github.com/advisories/GHSA-544c-gfhm-rwqf
  - https://github.com/advisories/GHSA-hf6p-xc3f-p4f9
  - https://github.com/advisories/GHSA-qff4-m3j5-xcv5
  - https://github.com/advisories/GHSA-r2pf-hp27-79jw
  - https://github.com/advisories/GHSA-j7p7-w7pr-mwpc
rules:
  - title: Detect Potential CVE-2026-42097 Exploitation Attempt
    description: Detects CVE-2026-42097 exploitation attempt — Monitors for POST requests to the Sparx Pro Cloud Server with a model name included in the binary blob, indicating a potential authentication bypass.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Suspicious PHP File Creation in Sparx Pro Cloud Server Repository
    description: Detects creation of PHP files within the Sparx Pro Cloud Server repository directory, which can be indicative of CVE-2026-42099 exploitation.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1505.003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On May 19, 2026, five vulnerabilities were disclosed affecting Sparx Systems Pro Cloud Server (versions up to 6.1 build 167) and Enterprise Architect (versions up to 17.1). These vulnerabilities include a critical authorization bypass (CVE-2026-42097) in Pro Cloud Server, and a high criticality Use of Client-Side Authentication vulnerability (CVE-2026-42098) in Enterprise Architect. Publicly available Proof-of-Concept (PoC) exploits exist for all five vulnerabilities (CVE-2026-42096, CVE-2026-42097, CVE-2026-42098, CVE-2026-42099, CVE-2026-42100), increasing the likelihood of active exploitation. Successful exploitation could lead to unauthorized data access, code execution, and denial-of-service. Defenders should prioritize patching vulnerable systems immediately.

## Attack Chain

1. An unauthenticated attacker sends a crafted POST request to the Sparx Pro Cloud Server, including a model name within the binary blob (CVE-2026-42097).
2. The server improperly validates the request, failing to authenticate the user, and allowing the attacker to bypass authorization.
3. The attacker leverages the bypass to execute arbitrary SQL queries against the underlying database without proper authentication.
4. The attacker gains unauthorized access to sensitive data stored within the database, potentially reading, modifying, or deleting information.
5. In a separate attack, an attacker with low privilege access exploits a race condition (CVE-2026-42099) by creating a malicious PHP file within the repository.
6. The attacker sends a request to execute the malicious PHP file. Due to delayed transmission response, the file can be executed even after deletion.
7. The malicious PHP code executes arbitrary commands on the server, potentially installing malware or creating backdoors.
8. The attacker achieves full system compromise, enabling further malicious activities such as data exfiltration or lateral movement.

## Impact

Successful exploitation of these vulnerabilities can lead to severe consequences. CVE-2026-42097 allows unauthenticated attackers to execute arbitrary SQL queries, potentially compromising sensitive data. CVE-2026-42098 allows attackers to bypass authentication and impersonate any user, leading to unauthorized modifications. CVE-2026-42099 enables arbitrary PHP code execution. CVE-2026-42100 can cause denial of service. The vulnerabilities collectively impact the confidentiality, integrity, and availability of affected systems. There is no mention of sectors targeted, or specific victim counts, but all users of unpatched Sparx Systems Pro Cloud Server and Enterprise Architect instances are at risk.

## Recommendation

*   Apply the latest patches for Sparx Systems Pro Cloud Server (<= 6.1 build 167) and Enterprise Architect (<= 17.1) to remediate the vulnerabilities detailed in this brief.
*   Monitor web server logs for suspicious POST requests targeting Sparx Pro Cloud Server with model names in the binary blob, indicative of CVE-2026-42097 exploitation.
*   Implement the Sigma rule "Detect Potential CVE-2026-42097 Exploitation Attempt" to identify potential exploitation attempts in web server logs.
*   Monitor for the creation and execution of unusual PHP files in the Sparx Pro Cloud Server repository directory, potentially indicating CVE-2026-42099 exploitation.
*   Deploy the Sigma rule "Detect Suspicious PHP File Creation in Sparx Pro Cloud Server Repository" to identify potentially malicious PHP files being created.
