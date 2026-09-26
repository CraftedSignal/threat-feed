---
title: Path Traversal in SiYuan Export Functionality
slug: 2026-09-siyuan-path-traversal
description: SiYuan versions prior to v3.8.4 are vulnerable to a path traversal attack via the exportBrowserHTML endpoint, allowing authenticated administrators to overwrite arbitrary index.html files.
date: "2026-09-26T15:03:37Z"
lastmod: "2026-09-26T15:05:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan:siyuan:*:*:*:*:*:*:*:*
vendors:
  - SiYuan
products:
  - SiYuan (< 3.8.4)
  - SiYuan (>= 2.1.0, < 3.8.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SiYuan versions before v3.8.4 contain a path traversal vulnerability in the exportBrowserHTML endpoint that allows authenticated administrators to write arbitrary HTML content.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Because the shared Lute renderer parses Kramdown IAL from text/plain input, an attacker-supplied Markdown snippet using entity-encoded quotes in data-subtype breaks out of the attribute value when the gutter markup is re-parsed by the browser, injecting additional attributes such as autofocus and onfocus.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1505
    technique_name: Server Software Component
    evidence: SiYuan before v3.8.4 does not HTML-escape stored flashcard block content before interpolating it into the card-manager list markup.
    confidence_band: high
cves:
  - id: CVE-2026-100636
    cvss: 7.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100636
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100639
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100641
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100642
rules:
  - title: Detect CVE-2026-100636 Path Traversal Attempt
    description: Detects exploitation attempts against the SiYuan exportBrowserHTML endpoint using directory traversal sequences in the folder parameter.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade SiYuan to v3.8.4
      owner: IT Operations
      due: 48h
      evidence: Source states SiYuan versions before v3.8.4 are vulnerable.
  hunt_leads:
    - lead: Logs showing POST requests to /exportBrowserHTML with traversal sequences
      technique_id: T1190
      data_needed:
        - webserver logs
      priority: medium
      confidence: high
      disposition: convert_to_detection
      evidence: Vulnerability allows directory traversal via folder parameter in this specific endpoint.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to v3.8.4
      owner: IT Operations
      addresses: CVE-2026-100636
      evidence: NVD vulnerability notice
updates:
  - at: "2026-09-26T15:05:28Z"
    level: L2
    summary: added coverage for SiYuan (< 3.8.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100639
  - at: "2026-09-26T15:05:49Z"
    level: L2
    summary: added coverage for SiYuan (< 3.8.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100641
  - at: "2026-09-26T15:05:54Z"
    level: L2
    summary: added coverage for SiYuan (>= 2.1.0, < 3.8.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-100642
---

SiYuan versions prior to v3.8.4 contain a critical path traversal vulnerability in the exportBrowserHTML endpoint. This flaw allows an authenticated administrator to manipulate the folder parameter by including directory traversal sequences. By successfully exploiting this, an attacker can escape the restricted export directory and overwrite the index.html file in any location that the application kernel has write permissions to. This vulnerability poses a significant risk for stored Cross-Site Scripting (XSS) attacks or workspace defacement, as it allows the injection of arbitrary HTML content into the application environment. Defenders should prioritize updating to SiYuan v3.8.4 or later to mitigate this risk.

## Impact

The vulnerability allows authenticated administrators to perform arbitrary file writes, leading to potential stored XSS or full application-level defacement. If compromised, an attacker could inject malicious scripts into the index.html file, which would then be executed in the context of other users or administrators accessing the application, facilitating further account takeover or malicious redirections.

## Recommendation

* Upgrade all SiYuan installations to version v3.8.4 or later immediately.
* Audit web server logs for suspicious POST requests to the exportBrowserHTML endpoint containing path traversal characters like '../' or '..%2f'.
* Restrict administrative access to the SiYuan interface to trusted personnel to limit the attack surface for this authenticated vulnerability.
