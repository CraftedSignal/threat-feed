---
title: Multiple Vulnerabilities in Google Chrome
slug: 2026-10-google-chrome-vulnerabilities
description: Google Chrome contains multiple vulnerabilities that can be exploited by a remote, anonymous attacker to achieve arbitrary code execution or cause a denial-of-service condition.
date: "2026-10-16T16:29:40Z"
lastmod: "2026-10-16T16:33:47Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - browser
  - vulnerability
  - remote-code-execution
vendors:
  - Google
products:
  - Chrome (< 155.0.8059.39)
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A remote, anonymous attacker can exploit multiple vulnerabilities in Google Chrome to execute arbitrary program code.
    confidence_band: high
cves:
  - id: CVE-2026-106289
    cvss: 6.5
    epss: 0.00229
  - id: CVE-2026-106292
    cvss: 8.3
    epss: 0.00332
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3982
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-106289
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-106292
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Chrome to 155.0.8059.39 or later
      owner: IT Operations
      due: 48h
      evidence: Vendor release notes for Google Chrome security updates.
  mitigation_plan:
    - priority: immediate
      action: Enforce auto-update policies via GPO or MDM.
      owner: IT Operations
      addresses: Google Chrome vulnerabilities
      evidence: BSI vulnerability report
updates:
  - at: "2026-10-16T16:33:41Z"
    level: L2
    summary: added CVE-2026-106289;, CVE-2026-106292
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-106289
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-106292
---

The German Federal Office for Information Security (BSI) has reported that Google Chrome is affected by multiple security vulnerabilities. These flaws allow a remote, anonymous attacker to trigger arbitrary code execution (ACE) or a denial-of-service (DoS) condition on vulnerable systems. The vulnerabilities affect Google Chrome across Windows, Linux, and macOS platforms. Given the ubiquity of the browser as an entry point for web-based attacks, these vulnerabilities represent a significant risk to organizational environments if left unpatched. Defenders should prioritize updating browser instances to the latest stable release provided by Google to mitigate the risk of remote compromise.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to execute arbitrary code within the context of the browser, potentially leading to full system compromise if chained with sandbox escapes. Alternatively, an attacker could cause a DoS condition, impacting browser availability and productivity. These vulnerabilities affect all major desktop operating systems running Google Chrome.

## Recommendation

* Monitor and enforce the update of all Google Chrome browser instances to the latest version as specified in the official Google Chrome release notes.
* Audit software inventories to identify and remediate outdated versions of Google Chrome across the fleet.
* Disable unused browser extensions and enforce a restrictive extension policy to reduce the attack surface for potential remote exploitation.
