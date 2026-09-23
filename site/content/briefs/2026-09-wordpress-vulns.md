---
title: Multiple Vulnerabilities in WordPress
slug: 2026-09-wordpress-vulns
description: WordPress is susceptible to multiple vulnerabilities that may allow unauthenticated attackers to achieve remote code execution, bypass security controls, perform cross-site scripting, or access sensitive data.
date: "2026-09-21T13:51:42Z"
lastmod: "2026-09-23T01:50:56Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=5F650CE9-222D-5AA8-A6CC-240BDBDE6253&utm_source=rss&utm_medium=rss
tags:
  - wordpress
  - web-vulnerability
  - cms
vendors:
  - WordPress
products:
  - WordPress
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can exploit multiple vulnerabilities in WordPress to execute arbitrary program code, bypass security measures, conduct cross-site scripting attacks, or manipulate and disclose data.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit multiple vulnerabilities in WordPress to execute arbitrary program code.
    confidence_band: high
cves:
  - id: CVE-2026-87902
    cvss: 8.1
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3472
  - https://www.securityweek.com/wordpress-patches-click2shell-vulnerability/
  - https://sploitus.com/exploit?id=5F650CE9-222D-5AA8-A6CC-240BDBDE6253&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all internal and external WordPress deployments
      owner: IT Operations
      due: 24h
      evidence: General vulnerability impact necessitates environment awareness
  mitigation_plan:
    - priority: immediate
      action: Upgrade all WordPress installations to the latest security release
      owner: IT Operations
      addresses: Multiple WordPress vulnerabilities
      evidence: Standard security practice for reported platform vulnerabilities
updates:
  - at: "2026-09-23T01:50:56Z"
    level: L2
    summary: poc_available; added CVE-2026-87902
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=5F650CE9-222D-5AA8-A6CC-240BDBDE6253&utm_source=rss&utm_medium=rss
---

The BSI has reported multiple vulnerabilities affecting WordPress, a widely used content management system. These flaws collectively expose environments to critical risks, including remote code execution (RCE), the bypassing of established security restrictions, cross-site scripting (XSS), and unauthorized data manipulation or disclosure. The vulnerabilities affect the core platform, potentially impacting any deployment currently utilizing unpatched versions. Defenders should prioritize auditing their WordPress instances to identify active versions and assess exposure based on the underlying vulnerability landscape. Organizations are advised to monitor official vendor security updates to address these weaknesses, as exploitation could lead to full site compromise or data breach depending on the specific attack vector employed against these vulnerabilities.

## Impact

Successful exploitation of these vulnerabilities can lead to full site compromise, allowing attackers to execute arbitrary commands, exfiltrate sensitive site data, modify content, or inject malicious scripts into pages viewed by legitimate users. This impacts all sectors utilizing WordPress for public-facing websites, internal portals, or e-commerce platforms.

## Recommendation

Prioritize monitoring for anomalous traffic patterns directed at WordPress core endpoints. Review web server access logs for requests containing suspicious payloads or high volumes of 4xx/5xx status codes indicating exploitation attempts. Ensure WordPress core and all plugins are updated to the latest available security release to mitigate the risk of these vulnerabilities.

## Impact
