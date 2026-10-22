---
brief_id: brief-2026-10-22-dedecms-code-injection
event_id: brief-2026-10-22-dedecms-code-injection
revision: 1
activity_at: "2026-10-22T12:02:02Z"
title: 'DedeCMS: PHP code injection in ShowMsg() (CVE-2021-48016)'
slug: 2026-10-dedecms-code-injection
description: DedeCMS through 5.8.1-beta contains a PHP code injection vulnerability in the ShowMsg() function, allowing unauthenticated attackers to execute arbitrary system commands via a crafted HTTP Referer header.
date: "2026-10-22T12:02:02Z"
type: threat
types:
  - threat
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:dedecms:dedecms:*:*:*:*:*:*:*:*
tags:
  - php-injection
  - remote-code-execution
  - web-application-vulnerability
vendors:
  - DedeCMS
products:
  - DedeCMS (<= 5.8.1-beta)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can send a crafted Referer to /plus/flink.php?dopost=save with an empty validate code to execute arbitrary PHP and system commands.
    confidence_band: high
cves:
  - id: CVE-2021-48016
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2021-48016
rules:
  - title: Detects CVE-2021-48016 Exploitation - PHP Code Injection via Referer Header
    description: Detects attempts to exploit the DedeCMS ShowMsg() vulnerability by checking for common PHP injection patterns within the HTTP Referer header sent to the flink.php endpoint.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Scan for DedeCMS installations
      owner: SOC
      due: 24h
      evidence: Vulnerability in DedeCMS versions <= 5.8.1-beta
  mitigation_plan:
    - priority: immediate
      action: Disable the affected flink.php endpoint or apply WAF filtering
      owner: IT Operations
      addresses: CVE-2021-48016
      evidence: Vulnerability is exploited via /plus/flink.php
---

DedeCMS versions through 5.8.1-beta are vulnerable to PHP code injection within the ShowMsg() function. The vulnerability arises because the application improperly handles the HTTP Referer header, writing it directly into a DedeTemplate string before inclusion. An unauthenticated attacker can exploit this by sending a crafted HTTP request to the '/plus/flink.php?dopost=save' endpoint with an empty validate code field. Successful exploitation results in arbitrary PHP and system command execution. This vulnerability has been subject to in-the-wild exploitation since at least October 14, 2023.

## Attack Chain
1. Attacker identifies a target running DedeCMS 5.8.1-beta or earlier.
2. Attacker crafts a malicious HTTP request targeting '/plus/flink.php?dopost=save'.
3. Attacker includes a malicious payload within the 'Referer' header.
4. Attacker ensures the 'validate' parameter is empty to bypass simple verification.
5. The server-side ShowMsg() function processes the crafted 'Referer' header.
6. The application writes the 'Referer' value into a template string and includes it.
7. Arbitrary PHP code injected in the 'Referer' header is executed by the server.

## Impact
Successful exploitation allows unauthenticated remote attackers to execute arbitrary PHP code and system commands on the underlying host, potentially leading to full system compromise.

## Recommendation
- Inventory all internet-facing instances of DedeCMS.
- Patch affected instances immediately; confirm if the vendor has provided a specific update that remediates the ShowMsg() injection vulnerability.
- If a patch is unavailable, restrict access to '/plus/flink.php' at the web application firewall or reverse proxy level.
- Enable detailed web server logging to capture 'Referer' headers and audit requests to the 'flink.php' endpoint for anomalous payloads containing PHP tags or shell commands.
