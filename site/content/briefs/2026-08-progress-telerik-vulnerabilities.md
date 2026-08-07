---
title: Multiple Critical Vulnerabilities in Progress Telerik UI for ASP.NET AJAX
slug: 2026-08-progress-telerik-vulnerabilities
description: Progress Telerik UI for ASP.NET AJAX is affected by a suite of thirteen critical vulnerabilities, including insecure deserialization, path traversal, XXE, and SSRF, which collectively enable remote code execution and data theft.
date: "2026-08-07T15:21:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:progress:telerik_ui_for_asp.net_ajax:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - web-application
  - rce
  - srf
vendors:
  - Progress
products:
  - Telerik UI for ASP.NET AJAX
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: De multiples vulnérabilités ont été découvertes dans Progress Telerik. Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1505.003
    technique_name: 'Server Software Component: Web Shell'
    evidence: Certaines d'entre elles permettent à un attaquant de provoquer une exécution de code arbitraire à distance.
    confidence_band: high
cves:
  - id: CVE-2026-13181
    cvss: 8.1
    epss: 0.00452
  - id: CVE-2026-13192
    cvss: 6.5
    epss: 0.00244
  - id: CVE-2026-14865
    cvss: 5.3
    epss: 0.00238
  - id: CVE-2026-14932
    cvss: 6.5
    epss: 0.00209
  - id: CVE-2026-13183
    cvss: 7.5
    epss: 0.00298
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0977/
  - https://www.cve.org/CVERecord?id=CVE-2026-13181
  - https://www.cve.org/CVERecord?id=CVE-2026-13182
  - https://www.cve.org/CVERecord?id=CVE-2026-13183
  - https://www.cve.org/CVERecord?id=CVE-2026-13184
  - https://www.cve.org/CVERecord?id=CVE-2026-13185
  - https://www.cve.org/CVERecord?id=CVE-2026-13186
  - https://www.cve.org/CVERecord?id=CVE-2026-13187
  - https://www.cve.org/CVERecord?id=CVE-2026-13188
  - https://www.cve.org/CVERecord?id=CVE-2026-13189
  - https://www.cve.org/CVERecord?id=CVE-2026-13190
  - https://www.cve.org/CVERecord?id=CVE-2026-13192
  - https://www.cve.org/CVERecord?id=CVE-2026-14865
  - https://www.cve.org/CVERecord?id=CVE-2026-14932
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch all Telerik UI implementations to 2026.2.708 or later.
      owner: IT Operations
      due: 24h
      evidence: 'Systems affected: Telerik UI for AJAX versions antérieures à 2026.2.708 (2026 Q2 SP1)'
  mitigation_plan:
    - priority: immediate
      action: Identify and inventory all web applications utilizing Telerik UI components.
      owner: Security Operations
      addresses: All CVEs listed
      evidence: De multiples vulnérabilités ont été découvertes dans Progress Telerik.
---

Progress has disclosed thirteen critical security vulnerabilities affecting Telerik UI for ASP.NET AJAX versions prior to 2026.2.708 (2026 Q2 SP1). These flaws, identified as CVE-2026-13181 through CVE-2026-13192, and CVE-2026-14865 and CVE-2026-14932, encompass a wide range of attack vectors including insecure deserialization, path traversal, XML External Entity (XXE) injection, and Server-Side Request Forgery (SSRF). 

The vulnerabilities affect multiple components of the Telerik framework, such as RadAsyncUpload, RadEditor, and the framework's persistence and dialog handlers. Successful exploitation allows unauthenticated attackers to achieve remote code execution, perform unauthorized file reads, bypass security policies, or cause denial of service. Given the broad surface area and the potential for full system compromise via deserialization chains, organizations must prioritize patching all Telerik UI implementations to version 2026.2.708 or later.

## Impact

Successful exploitation of these vulnerabilities can lead to full system compromise, exfiltration of sensitive data, and persistent access within the affected infrastructure. Organizations using Telerik UI for public-facing web applications are at significant risk of unauthenticated remote exploitation. The combination of RCE and file-read capabilities poses a high risk to both internal data integrity and the availability of business-critical applications.

## Recommendation

* Immediately upgrade all instances of Telerik UI for ASP.NET AJAX to version 2026.2.708 or later.
* Review web server logs for requests targeting Telerik handlers (e.g., `RadAsyncUpload`, `DialogHandler`, `RadEditor`) that contain serialized objects, path traversal sequences (e.g., `../`), or unexpected XML entities.
* Restrict network access to Telerik management endpoints and file-upload handlers to trusted internal subnets where possible.
* Use vulnerability scanning tools to inventory all applications utilizing vulnerable versions of the Telerik DLLs.
