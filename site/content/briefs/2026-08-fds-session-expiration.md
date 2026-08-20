---
title: Insufficient Session Expiration in Frauscher Sensortechnik FDS 102
slug: 2026-08-fds-session-expiration
description: CVE-2026-14950 is an insufficient session expiration vulnerability in Frauscher Sensortechnik FDS 102 that allows an attacker with a valid session identifier to maintain access beyond the intended expiration time.
date: "2026-08-20T11:11:47Z"
lastmod: "2026-08-20T11:12:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve
  - vulnerability
  - rce
  - industrial-control-system
  - path-traversal
vendors:
  - Frauscher Sensortechnik
products:
  - FDS 102 (2.1.0 to 2.13.3)
  - FDS 102 (2.8.0-2.13.3)
  - FDS 102
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: An unauthenticated remote attacker in possession of a valid session identifier is able to continue using the session after it should have expired.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: An attacker can upload a .php file and then request it directly from /uploads/<filename>.php to achieve arbitrary code execution
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A high-privileged remote attacker can upload malicious ZIP archive containing directory traversal sequences such as ../ can escape the intended extraction directory and write files to arbitrary locations on the server, potentially achieve arbitrary code execution
    confidence_band: high
cves:
  - id: CVE-2026-14950
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14950
  - https://www.certvde.com/en/advisories/VDE-2026-078/
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14946
  - https://nvd.nist.gov/vuln/detail/CVE-2026-14947
rules:
  - title: Detect CVE-2026-14946 Exploitation - Unauthorized File Upload and Access
    description: Detects exploitation of CVE-2026-14946 by monitoring for HTTP requests to .php files within the /uploads/ directory.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1505.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade Frauscher Sensortechnik FDS 102 to the patched version.
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-14950 remediation
updates:
  - at: "2026-08-20T11:11:58Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-14946 Exploitation - Unauthorized File Upload and Access'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-14946
  - at: "2026-08-20T11:12:06Z"
    level: L2
    summary: added coverage for FDS 102
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-14947
---

CVE-2026-14950 identifies an insufficient session expiration flaw (CWE-613) within the web interface of the Frauscher Sensortechnik FDS 102 system, affecting versions 2.1.0 through 2.13.3. This vulnerability enables an unauthenticated attacker who has obtained a valid session identifier - potentially through interception, theft, or by leveraging an unattended machine - to continue using the session indefinitely, even after the system's expiration policy should have terminated it. This persistence mechanism allows unauthorized users to maintain an active, authenticated state, effectively bypassing standard session timeout security controls. Defenders should prioritize patching affected FDS 102 units and implement strict monitoring for anomalous session activity or unauthorized session token reuse.

## Impact

The vulnerability carries a CVSS v3.1 score of 9.8 (Critical), indicating high risk for unauthorized access and control over the affected FDS 102 interface. If exploited, an attacker gains persistent access to the management environment, potentially leading to unauthorized monitoring or configuration changes of sensitive industrial sensor systems. The vulnerability affects a critical component of industrial infrastructure management, and failure to apply available patches leaves systems open to prolonged unauthorized access.

## Recommendation

* Apply the security update provided by Frauscher Sensortechnik to all FDS 102 instances running version 2.13.3 or earlier to remediate CVE-2026-14950.
* Monitor web application logs for session tokens that persist beyond expected operational windows or show abnormal temporal patterns.
* Enforce strict session management policies, including idle timeouts and secure transport (HTTPS) to mitigate the risk of session identifier interception.
