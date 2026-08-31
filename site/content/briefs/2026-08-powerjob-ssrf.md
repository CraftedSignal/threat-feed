---
title: SSRF Vulnerability in PowerJob Transport Endpoint
slug: 2026-08-powerjob-ssrf
description: PowerJob versions up to 5.1.2 contain a server-side request forgery vulnerability in the MuConnectionManager component that allows remote, unauthenticated attackers to perform unauthorized network requests.
date: "2026-08-31T09:16:28Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:powerjob:powerjob:*:*:*:*:*:*:*:*
tags:
  - web-vulnerability
  - ssrf
  - remote-execution
vendors:
  - PowerJob
products:
  - PowerJob (<= 5.1.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation leads to server-side request forgery. The attack is possible to be carried out remotely.
    confidence_band: high
cves:
  - id: CVE-2026-82630
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82630
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to the PowerJob TestController endpoint via perimeter or host-based firewalls
      owner: IT Operations
      due: 24h
      evidence: Exploit is publicly available and impacts the transport endpoint
  mitigation_plan:
    - priority: immediate
      action: Monitor egress traffic from PowerJob server instances for suspicious connection attempts
      owner: SOC
      addresses: CVE-2026-82630
      evidence: Vulnerability allows unauthorized requests from the server's network location
---

A server-side request forgery (SSRF) vulnerability, assigned CVE-2026-82630, exists in PowerJob versions up to and including 5.1.2. The flaw is located in the `MuConnectionManager.getOrCreateConnection` function within the `TestController.java` file of the transport endpoint component. This vulnerability allows an unauthenticated remote attacker to manipulate network connections and force the PowerJob server to perform requests to internal or external network resources. Given the availability of public exploit material, there is a risk of unauthorized data access or interaction with internal services hosted within the same network as the PowerJob instance. The project maintainers have not yet provided a patch or formal response to the reported issue.

## Impact

Successful exploitation allows remote attackers to perform SSRF attacks, potentially leading to unauthorized access to internal services, metadata services, or sensitive data within the server's network perimeter. The scope of impact depends on the internal network architecture of the affected organization.

## Recommendation

* Monitor webserver access logs for anomalous requests to the `TestController` endpoint that deviate from baseline traffic patterns.
* Implement strict network egress filtering on the host running the PowerJob server to prevent unauthorized internal scanning or data exfiltration via SSRF.
* Evaluate the necessity of exposing the PowerJob instance to untrusted networks; restrict access using VPN or firewall rules until a security update is released.
* Monitor for any evidence of unauthorized requests sourced from the PowerJob server internal network segment.
