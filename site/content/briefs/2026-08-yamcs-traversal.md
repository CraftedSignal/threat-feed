---
title: Unauthenticated Directory Traversal in Yamcs
slug: 2026-08-yamcs-traversal
description: Yamcs versions prior to 5.11.13 contain an unauthenticated directory traversal vulnerability in the HTTP request handling components that allows remote attackers to read arbitrary files from the underlying host.
date: "2026-08-28T21:18:21Z"
lastmod: "2026-08-28T21:18:40Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yamcs:yamcs_core:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - directory-traversal
  - cve-2026-55552
  - privilege-escalation
  - web-application-vulnerability
vendors:
  - Yamcs
products:
  - yamcs-core (< 5.11.13)
  - yamcs-core (5.13.0-5.13.1)
  - yamcs-core (<= 5.12.7)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An Unauthenticated Directory Traversal vulnerability exists in Yamcs, allowing anyone to access any file on the underlying operating system.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This allows unauthenticated attackers to download sensitive files and data.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: These vulnerabilities allow any authenticated user, regardless of their assigned roles or privileges, to bypass intended access controls.
    confidence_band: high
cves:
  - id: CVE-2026-55552
    cvss: 7.5
references:
  - https://github.com/advisories/GHSA-9jg3-g3wh-w9pj
  - https://github.com/advisories/GHSA-962x-ccwf-8x6p
  - https://nvd.nist.gov/vuln/detail/CVE-2026-55521
rules:
  - title: Detect CVE-2026-55552 Exploitation - Directory Traversal in Yamcs
    description: Detects exploitation attempts against Yamcs by identifying directory traversal sequences in HTTP GET requests.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Unauthorized Yamcs Core API Administrative Actions
    description: Detects unauthorized attempts by users to call administrative endpoints in Yamcs Core API that are susceptible to CVE-2026-55521.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade yamcs-core to version 5.11.13 or later.
      owner: IT Operations
      due: 24h
      evidence: Source advisory confirms patch availability in 5.11.13.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 5.11.13
      owner: IT Operations
      addresses: CVE-2026-55552
updates:
  - at: "2026-08-28T21:18:40Z"
    level: L2
    summary: 'added detection rule: Detect Unauthorized Yamcs Core API Administrative Actions'
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-962x-ccwf-8x6p
---

Yamcs versions prior to 5.11.13 are susceptible to an unauthenticated directory traversal vulnerability (CVE-2026-55552) residing in the `HttpRequestHandler.java` and `StaticFileHandler.java` components. This flaw allows remote, unauthenticated attackers to bypass intended directory restrictions by crafting specific HTTP requests containing traversal sequences. An attacker can leverage this to retrieve sensitive system files, configuration files, or other data residing on the host filesystem where Yamcs is deployed. Given the nature of the application as a mission control system, exposure of sensitive configuration or authentication files poses a significant risk to the integrity and confidentiality of the entire environment.

## Impact

Successful exploitation grants an unauthenticated attacker the ability to read arbitrary files from the filesystem of the host running the Yamcs service. This can lead to the exfiltration of credentials, system configuration details, or sensitive operational data, potentially facilitating further unauthorized access or complete system compromise.

## Recommendation

1. Upgrade Yamcs to version 5.11.13 or later immediately to patch CVE-2026-55552.
2. Implement network-level access controls to restrict access to the Yamcs management interface to known, trusted IP ranges.
3. Deploy the provided Sigma rule to web server access logs to detect directory traversal attempts.
4. Perform a log review for any historical GET requests to the Yamcs interface containing '..' or unusual path indicators.
