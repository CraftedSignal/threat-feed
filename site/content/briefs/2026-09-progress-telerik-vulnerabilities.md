---
title: Critical Vulnerabilities in Progress Telerik UI for ASP.NET AJAX
slug: 2026-09-progress-telerik-vulnerabilities
description: Progress Software has patched two vulnerabilities, including path traversal (CVE-2026-18672) and input tampering (CVE-2026-19219), in Telerik UI for ASP.NET AJAX versions prior to 2026.3.812.
date: "2026-09-03T00:08:03Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progress:telerik_ui_for_asp_net_ajax:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - patch-management
vendors:
  - Progress
products:
  - Telerik UI for ASP.NET AJAX (< 2026.3.812)
cves:
  - id: CVE-2026-18672
    cvss: 7.5
  - id: CVE-2026-19219
    cvss: 8.1
references:
  - https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rie-path-traversal-cve-2026-18672
  - https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-dialoghandler-uploadpaths-tampering-cve-2026-19219
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Telerik UI for ASP.NET AJAX to 2026.3.812 or later
      owner: IT Operations
      due: 24h
      evidence: Source advisory states versions prior to 2026.3.812 are affected
  mitigation_plan:
    - priority: immediate
      action: Upgrade Telerik UI for ASP.NET AJAX to 2026.3.812
      owner: IT Operations
      addresses: CVE-2026-18672 and CVE-2026-19219
      evidence: Vendor security advisory
---

Progress Software has released a security advisory concerning two vulnerabilities impacting Telerik UI for ASP.NET AJAX. The affected versions include all releases prior to 2026.3.812. The first vulnerability, CVE-2026-18672, is a path traversal flaw residing within the RadImageEditor component, which could allow an attacker to read or manipulate files on the underlying web server. The second vulnerability, CVE-2026-19219, involves improper handling of the DialogHandler UploadPaths configuration, potentially enabling unauthorized file uploads or system tampering. These vulnerabilities pose a significant risk to organizations hosting ASP.NET web applications that rely on the Telerik UI framework, as successful exploitation could lead to full system compromise or sensitive data exposure. Defenders should immediately identify all instances of Telerik UI for ASP.NET AJAX within their environment and upgrade to version 2026.3.812 or later to eliminate these attack vectors.

## Impact

Successful exploitation of these vulnerabilities allows unauthorized remote actors to bypass security controls in ASP.NET web applications. CVE-2026-18672 could lead to arbitrary file read or write access on the host server, while CVE-2026-19219 could be leveraged to gain remote code execution or facilitate persistent backdoors via unauthorized file uploads. Organizations across all sectors utilizing vulnerable Progress Telerik components are at risk of data exfiltration and server takeover.

## Recommendation

Prioritize the identification and patching of all web applications using Progress Telerik UI for ASP.NET AJAX.

* Upgrade Telerik UI for ASP.NET AJAX to version 2026.3.812 or later immediately to resolve CVE-2026-18672 and CVE-2026-19219.
* Audit web server logs for irregular POST requests to the DialogHandler and unusual file access patterns in the web root that may indicate attempted path traversal via RadImageEditor.
* Implement strict file system permissions for the web application user to minimize the impact if path traversal is successfully exploited.
