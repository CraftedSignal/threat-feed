---
title: Unauthenticated RCE and SSRF in xiaobei via Webhook Injection
slug: 2026-09-xiaobei-unauth-webhook
description: The xiaobei product through version 5.5.2 lacks authentication on webhook endpoints, enabling unauthenticated remote code execution via pipeline message injection and server-side request forgery (SSRF) via malicious media URL fetching.
date: "2026-09-04T15:26:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:xiaobei:xiaobei:*:*:*:*:*:*:*:*
tags:
  - webserver
  - vulnerability
  - cve
vendors:
  - xiaobei
products:
  - xiaobei (<= 5.5.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: xiaobei through 5.5.2 fails to implement authentication or signature validation on webhook endpoints, allowing unauthenticated attackers to inject arbitrary messages.
    confidence_band: high
cves:
  - id: CVE-2026-85667
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85667
rules:
  - title: Detects CVE-2026-85667 Exploitation - Unauthenticated Webhook Access
    description: Detects unauthenticated HTTP POST requests to the xiaobei webhook handler that may indicate pipeline injection or SSRF attempts
    platform: sigma
    severity: critical
    tactics:
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
    - action: Restrict external access to /webhook_worktool at the WAF level
      owner: IT Operations
      due: 24h
      evidence: Source confirms endpoint lacks authentication
  mitigation_plan:
    - priority: immediate
      action: Upgrade xiaobei to version > 5.5.2
      owner: IT Operations
      addresses: CVE-2026-85667
      evidence: NVD vulnerability disclosure
---

The xiaobei application, up to and including version 5.5.2, contains a critical vulnerability where webhook endpoints fail to implement necessary authentication or signature validation. This flaw allows unauthenticated remote attackers to interact directly with the application's internal messaging pipeline via the /webhook_worktool handler. By submitting crafted payloads, an attacker can inject arbitrary messages, leading to potential remote code execution (RCE) within the agent pipeline. Furthermore, the application processes media URLs provided via these webhooks without adequate validation. This behavior can be exploited by attackers to conduct server-side request forgery (SSRF) attacks, allowing them to probe or interact with services located within the internal network that are otherwise inaccessible from the public internet. Given the lack of defensive controls on these endpoints, organizations using xiaobei versions 5.5.2 and earlier are at high risk of unauthorized system access and internal service compromise.

## Impact

Successful exploitation of CVE-2026-85667 allows an unauthenticated attacker to execute code within the agent pipeline and leverage the server to reach internal network resources. This poses a significant threat of data exfiltration, lateral movement, and total system compromise.

## Recommendation

* Immediately restrict network access to the /webhook_worktool endpoint to known, trusted IP addresses using a reverse proxy or Web Application Firewall (WAF).
* Audit all incoming webhook traffic for anomalous payloads targeting internal internal service URLs.
* Upgrade xiaobei to a version released after 5.5.2 that implements cryptographic signature validation for webhook requests (CVE-2026-85667).
