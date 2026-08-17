---
title: Authorization Bypass in GL.iNet WebDAV Service
slug: 2026-08-glinet-webdav-auth-bypass
description: Multiple GL.iNet router models running firmware versions up to 4.8.x contain an authorization bypass vulnerability in the WebDAV service, allowing remote unauthenticated attackers to manipulate file operations.
date: "2026-08-17T04:43:39Z"
lastmod: "2026-08-17T04:43:47Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-19980
  - remote-code-execution
  - network-security
  - firmware-vulnerability
vendors:
  - GL.iNet
products:
  - A1300
  - AX1800
  - AXT1800
  - BE1400
  - BE3600
  - BE6500
  - BE9300
  - BE10000
  - E5800
  - MT2500
  - MT3000
  - MT3600BE
  - MT5000
  - MT6000
  - X2000
  - X3000
  - XE3000
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Performing a manipulation of the argument hour/min/week results in code injection.
    confidence_band: high
cves:
  - id: CVE-2026-19979
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19979
  - https://nvd.nist.gov/vuln/detail/CVE-2026-19980
rules:
  - title: Detect CVE-2026-19979 Exploitation - WebDAV COPY/MOVE Methods
    description: Detects unauthorized usage of WebDAV COPY or MOVE methods, which are indicators of potential exploitation of the authorization bypass vulnerability.
    platform: sigma
    severity: high
    tactics:
      - persistence
    techniques:
      - T1505.004
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch firmware to 4.8.x or later
      owner: IT Operations
      due: 48h
      evidence: Vendor recommendation for CVE-2026-19979
    - action: Disable WebDAV service
      owner: IT Operations
      due: 24h
      evidence: Vulnerability exists in WebDAV service
  mitigation_plan:
    - priority: immediate
      action: Restrict WebDAV access to internal management IPs
      owner: IT Operations
      addresses: CVE-2026-19979
      evidence: CVE-2026-19979 remote exploitation potential
updates:
  - at: "2026-08-17T04:43:47Z"
    level: L2
    summary: added coverage for A1300 +16 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-19980
---

GL.iNet has confirmed an authorization bypass vulnerability identified as CVE-2026-19979 affecting numerous router models, including the A1300, AX1800, AXT1800, BE series, E5800, MT series, and X series. The issue resides within the WebDAV service component of the device firmware. Specifically, the flaw exists in the processing of the COPY and MOVE functions, which are improperly validated. This vulnerability allows a remote, unauthenticated attacker to manipulate these functions to circumvent existing access controls. By exploiting this flaw, an attacker can perform unauthorized file operations on the router's file system. Given the remote accessibility of the WebDAV interface, organizations and individual users should treat this as a significant security risk. Affected devices running firmware versions up to 4.8.x are susceptible.

## Impact

Successful exploitation of this vulnerability results in an authorization bypass, enabling unauthorized file manipulation on the target router. This can lead to the exfiltration of sensitive configuration files, unauthorized data modification, or the potential deployment of malicious payloads if file upload paths are leveraged. The impact is critical for administrative integrity of network edge devices.

## Recommendation

- Update all affected GL.iNet router firmware to version 4.8.x or the latest available stable release provided by the vendor.
- Disable the WebDAV service on all GL.iNet devices if it is not explicitly required for business operations.
- Restrict access to the router's management interfaces and administrative services to trusted management subnets or via VPN only, preventing exposure to the internet.
- Audit network logs for unauthorized HTTP/WebDAV methods (COPY, MOVE) originating from external IP addresses toward managed infrastructure.
