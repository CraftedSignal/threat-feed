---
title: CVE-2021-23758 - Ajax.NET Professional Deserialization Vulnerability
slug: 2026-08-ajaxnet-deserialization
description: Ajax.NET Professional contains a deserialization of untrusted data vulnerability (CVE-2021-23758) that could allow remote attackers to achieve code execution through malicious .NET class payloads.
date: "2026-08-26T23:09:49Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:ajaxpro.2_project:ajaxpro.2:*:*:*:*:*:.net:*:*
  - cpe:2.3:a:michaelschwarz:ajax.net_professional:*:*:*:*:*:.net:*:*
products:
  - Ajax.NET Professional
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Ajax.NET Professional (AjaxPro) contains a deserialization of untrusted data vulnerability that could allow for remote code execution via arbitrary .NET classes.
    confidence_band: high
cves:
  - id: CVE-2021-23758
    cvss: 8.1
    epss: 0.89096
references:
  - https://www.cve.org/CVERecord?id=CVE-2021-23758
  - https://nvd.nist.gov/vuln/detail/CVE-2021-23758
  - https://github.com/michaelschwarz/Ajax.NET-Professional/commit/b0e63be5f0bb20dfce507cb8a1a9568f6e73de57
  - https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all applications for presence of Ajax.NET Professional library.
      owner: IT Operations
      due: 24h
      evidence: CISA BOD 26-04 compliance requirements
  mitigation_plan:
    - priority: immediate
      action: Remove or replace the vulnerable Ajax.NET Professional library.
      owner: IT Operations
      addresses: CVE-2021-23758
      evidence: CISA-KEV vulnerability directive
---

Ajax.NET Professional (AjaxPro), an open-source library used to integrate AJAX functionality into .NET applications, is vulnerable to a deserialization of untrusted data flaw identified as CVE-2021-23758. An attacker can exploit this vulnerability by sending crafted input that triggers the deserialization of arbitrary .NET classes, potentially leading to remote code execution (RCE) on the host server. The component is currently considered end-of-life and end-of-service, leaving it without official security maintenance. CISA has added this vulnerability to the Known Exploited Vulnerabilities (KEV) catalog and mandates that organizations prioritize patching or discontinue use of the component as per BOD 26-04 guidelines. Given the nature of the library as a third-party dependency, it may be embedded within various proprietary and legacy applications, making discovery and inventory critical for defense.

## Impact

Successful exploitation allows remote, unauthenticated attackers to execute arbitrary code within the context of the application server. This could lead to full system compromise, data exfiltration, or lateral movement within the network. Because the library is often used as a hidden dependency in older web applications, the total number of exposed instances across critical sectors is unknown but poses a significant risk to legacy infrastructure.

## Recommendation

* Conduct an immediate inventory of all applications within the environment to identify the presence of the Ajax.NET Professional library.
* As the component is EoL/EoS, discontinue use of the library and migrate to supported alternatives immediately.
* If immediate removal is not possible, implement strict network ingress filtering to block access to application paths utilizing AjaxPro until the application can be decommissioned or the dependency removed.
* Ensure compliance with CISA BOD 26-04 by evaluating internet-exposed assets for the presence of this vulnerability and implementing compensating controls where patching is not possible.
* Review web server access logs for anomalous POST requests directed at application endpoints that rely on AjaxPro, as this is the primary vector for delivering the malicious payload.
