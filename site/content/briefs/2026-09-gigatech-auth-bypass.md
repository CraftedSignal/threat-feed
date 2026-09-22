---
title: Critical Authentication Bypass in Gigatech PDV5701 WebSocket Service
slug: 2026-09-gigatech-auth-bypass
description: A critical authentication bypass vulnerability (CVE-2026-94493) in Gigatech PDV5701 allows remote, unauthenticated access via the /index.html component of the WebSocket Service.
date: "2026-09-22T02:32:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:gigatech:pdv5701:1.0.31_240305_112640:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-access
  - websocket
  - networking
vendors:
  - Gigatech
products:
  - PDV5701 (1.0.31_240305_112640)
cves:
  - id: CVE-2026-94493
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94493
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Isolate affected Gigatech PDV5701 devices from public-facing segments
      owner: IT Operations
      due: 24h
      evidence: Source notes remote exploitability and CVSS 10.0 rating
  mitigation_plan:
    - priority: immediate
      action: Implement firewall rules to block unauthorized external access to the WebSocket Service endpoint
      owner: IT Operations
      addresses: CVE-2026-94493
      evidence: NVD vulnerability details regarding missing authentication
---

CVE-2026-94493 is a critical vulnerability affecting Gigatech PDV5701 firmware version 1.0.31_240305_112640. The vulnerability resides within the WebSocket Service component, specifically involving the improper processing of requests to the /index.html file. Due to missing authentication controls, a remote, unauthenticated attacker can exploit this flaw to bypass security mechanisms. This vulnerability has been publicly disclosed, and exploitation code is available, increasing the risk of unauthorized access or full system compromise. Gigatech has not provided a patch or a response to the disclosure. Defenders should prioritize network-level inspection to identify unauthorized attempts to interact with the WebSocket Service or index.html endpoint on affected devices.

## Impact

Successful exploitation allows remote attackers to bypass authentication entirely, resulting in unauthorized access to the device. Given the CVSS 3.1 base score of 10.0, this represents a complete compromise of the system's security posture, potentially allowing for remote command execution, data exfiltration, or persistence within the targeted environment.

## Recommendation

- Identify all instances of Gigatech PDV5701 within the internal network infrastructure.
- Implement network-level access control lists (ACLs) to restrict access to the WebSocket Service endpoint on affected Gigatech PDV5701 devices, ensuring only authorized management subnets can communicate with the interface.
- Monitor logs for repeated or unauthorized HTTP requests to /index.html on Gigatech hardware, as this may indicate exploitation attempts.
- Since no vendor patch is currently available, consider isolating these devices behind a VPN or dedicated management gateway to mitigate remote exposure.
