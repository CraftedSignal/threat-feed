---
title: Prototype Pollution Vulnerability in Payload Import Export Plugin
slug: 2026-10-payload-prototype-pollution
description: An unauthenticated prototype pollution vulnerability in the Payload Import Export plugin allows remote attackers to achieve code execution via malicious input.
date: "2026-10-06T18:45:50Z"
lastmod: "2026-10-07T20:51:04Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:payload:plugin_import_export:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=73BE1B4F-C08C-5F0A-9943-93A0A290FB8E&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - prototype-pollution
  - rce
  - supply-chain
vendors:
  - Payload
products:
  - plugin-import-export (3.0.0 - 3.87.9)
  - plugin-import-export (4.0.0-canary.0 - 4.0.0-canary.26)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated user could cause unintended application behavior when the Import Export plugin is enabled.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: allowing an attacker to submit and execute remote code (RCE).
    confidence_band: high
cves:
  - id: CVE-2026-105844
references:
  - https://github.com/advisories/GHSA-qf28-8hc6-vwrp
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-105844
  - https://sploitus.com/exploit?id=73BE1B4F-C08C-5F0A-9943-93A0A290FB8E&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade @payloadcms/plugin-import-export to version 3.88.0 or 4.0.0-canary.27.
      owner: IT Operations
      due: 24h
      evidence: Patches section identifies these versions as addressing the vulnerability.
  mitigation_plan:
    - priority: immediate
      action: Disable the Import Export plugin in production environments.
      owner: IT Operations
      addresses: CVE-2026-105844
      evidence: Workarounds section suggests disabling the plugin as a primary mitigation.
updates:
  - at: "2026-10-07T20:51:04Z"
    level: L2
    summary: poc_available
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=73BE1B4F-C08C-5F0A-9943-93A0A290FB8E&utm_source=rss&utm_medium=rss
---

A prototype pollution vulnerability has been identified in the @payloadcms/plugin-import-export package, tracked as CVE-2026-105844. This vulnerability affects versions 3.0.0 through 3.87.9 and canary versions between 4.0.0-canary.0 and 4.0.0-canary.26. The flaw exists within the plugin's data handling logic, which fails to properly sanitize input before processing. An unauthenticated attacker can exploit this weakness by submitting specifically crafted JSON payloads to the plugin's endpoints. By polluting the object prototype, the attacker can influence application-wide behavior, potentially leading to remote code execution (RCE). This issue is limited to environments where the Import Export plugin is explicitly enabled.

## Impact

Successful exploitation allows an unauthenticated attacker to achieve remote code execution within the context of the Payload CMS application. This could result in full system compromise, data theft, or service disruption. All organizations utilizing the affected plugin version are at risk if the application is internet-facing or accessible to untrusted users.

## Recommendation

- Upgrade the @payloadcms/plugin-import-export package to version 3.88.0 or 4.0.0-canary.27 or later.
- If an immediate upgrade is not feasible, disable the Import Export plugin entirely or implement strict network-level access controls to restrict access to the plugin's API endpoints.
- Monitor web application logs for unexpected JSON structures or suspicious requests directed at import or export functional routes.
