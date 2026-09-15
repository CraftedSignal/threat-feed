---
title: Remote Code Execution Vulnerability in WebKitGTK
slug: 2026-09-webkitgtk-rce
description: A memory corruption vulnerability in WebKitGTK allows a remote, unauthenticated attacker to execute arbitrary code or trigger a denial-of-service condition by processing maliciously crafted web content.
date: "2026-09-15T13:06:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:webkitgtk:webkitgtk:*:*:*:*:*:*:*:*
  - cpe:2.3:o:apple:macos:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - linux
products:
  - WebKitGTK (< 2.46.0)
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: A remote, unauthenticated attacker can exploit this flaw by enticing a user to navigate to a maliciously crafted web page.
    confidence_band: high
cves:
  - id: CVE-2024-44224
    cvss: 7.8
    epss: 0.00253
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3107
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade WebKitGTK to version 2.46.0 or later
      owner: IT Operations
      addresses: CVE-2024-44224
      evidence: Source advisory recommends version 2.46.0 for remediation
---

WebKitGTK, the port of the WebKit engine to the GTK framework, contains a memory corruption vulnerability identified as CVE-2024-44224. This vulnerability affects versions prior to 2.46.0. An unauthenticated, remote attacker can exploit this flaw by enticing a user to navigate to a maliciously crafted web page. Successful exploitation of this memory corruption issue allows an attacker to achieve arbitrary code execution within the context of the application using the WebKitGTK engine, or alternatively, crash the application to trigger a denial-of-service state. Given the widespread use of WebKitGTK in various desktop Linux applications and browsers, the impact is significant for organizations running affected Linux distributions. Organizations should prioritize updating WebKitGTK to version 2.46.0 or later to mitigate this risk.

## Impact

Successful exploitation may result in full remote code execution on the end-user system or service disruption through application crashes. The vulnerability affects any application utilizing the vulnerable WebKitGTK engine, potentially impacting enterprise Linux workstations and embedded systems across multiple sectors.

## Recommendation

Update all systems and applications using the WebKitGTK engine to version 2.46.0 or later immediately. Ensure patch management cycles are applied to Linux distributions that maintain system-wide WebKitGTK libraries.
