---
title: Remote Code Execution via Deserialization in Open-Web-Analytics
slug: 2026-09-open-web-analytics-deserialization
description: Open-Web-Analytics up to version 1.8.1 contains a remote deserialization vulnerability in the Remote Event Queue Endpoint that allows unauthenticated attackers to execute arbitrary code.
date: "2026-09-25T14:53:29Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:open_web_analytics:open_web_analytics:*:*:*:*:*:*:*:*
tags:
  - web-application
  - deserialization
  - rce
vendors:
  - Open-Web-Analytics
products:
  - Open-Web-Analytics (<= 1.8.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack can be initiated remotely via the Remote Event Queue Endpoint.
    confidence_band: high
cves:
  - id: CVE-2026-97865
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-97865
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Open-Web-Analytics to 1.8.2
      owner: IT Operations
      due: 24h
      evidence: 'Source states: Upgrading to version 1.8.2 is able to address this issue.'
  mitigation_plan:
    - priority: immediate
      action: Patch OWA using commit 78c1222ec0e2119d84684032da1541120a2cdd23
      owner: IT Operations
      addresses: CVE-2026-97865
      evidence: The patch is named 78c1222ec0e2119d84684032da1541120a2cdd23.
---

A deserialization vulnerability exists in the Open-Web-Analytics (OWA) platform, specifically affecting versions 1.8.1 and earlier. The flaw resides within the `Event::loadFromArray` function located in the `queue.php` file, which is part of the Remote Event Queue Endpoint component. An unauthenticated remote attacker can exploit this vulnerability by sending a maliciously crafted payload to the endpoint, leading to insecure deserialization. Successful exploitation allows for arbitrary code execution on the underlying web server. Defenders should immediately upgrade to OWA version 1.8.2 or apply the official patch (78c1222ec0e2119d84684032da1541120a2cdd23) to mitigate this high-severity risk.

## Impact

Successful exploitation of this vulnerability results in full remote code execution on the web server hosting Open-Web-Analytics. This could lead to a complete system compromise, unauthorized access to sensitive analytics data, or the use of the server as a pivot point for lateral movement within the network.

## Recommendation

* Upgrade Open-Web-Analytics to version 1.8.2 immediately to remediate CVE-2026-97865.
* If an immediate upgrade is not possible, apply the specific patch 78c1222ec0e2119d84684032da1541120a2cdd23.
* Monitor web server access logs for anomalous POST requests directed at the `queue.php` endpoint that contain serialized object structures or unusual query parameters.
