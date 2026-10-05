---
title: Authentication Bypass in Totolink A3002MU via /bin/boa
slug: 2026-10-totolink-auth-bypass
description: The Totolink A3002MU router (v1.0.0-B20230403.1455) contains a critical authentication bypass vulnerability in the /bin/boa web server component, allowing remote unauthenticated access.
date: "2026-10-05T09:39:21Z"
type: threat
types:
  - threat
severities:
  - critical
exploited: true
cpes:
  - cpe:2.3:o:totolink:a3002mu_firmware:1.0.0-b20230403.1455:*:*:*:*:*:*:*
tags:
  - authentication-bypass
  - network-device
  - web-vulnerability
vendors:
  - Totolink
products:
  - A3002MU (1.0.0-B20230403.1455)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Executing a manipulation can lead to improper authorization.
    confidence_band: high
cves:
  - id: CVE-2026-105284
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-105284
action_plan:
  priority: elevated
  owners:
    - Network Operations
    - SOC
  immediate_actions:
    - action: Disable WAN-side access to the Totolink web management interface
      owner: Network Operations
      due: 24h
      evidence: The attack may be launched remotely.
  mitigation_plan:
    - priority: immediate
      action: Restrict web management interface (port 80/443) access to authorized management subnets only
      owner: Network Operations
      addresses: CVE-2026-105284
      evidence: CVE-2026-105284 authentication bypass
---

A critical authentication bypass vulnerability has been identified in the Totolink A3002MU wireless router, specifically affecting firmware version 1.0.0-B20230403.1455. The vulnerability resides within the function `sub_40FCFC` located in the `/bin/boa` binary, which serves as the router's embedded web management interface. 

The flaw allows a remote, unauthenticated attacker to manipulate the authentication check process, resulting in improper authorization. Given that the web service runs with elevated privileges on the device, successful exploitation provides an attacker with administrative-level access to the router's configuration. A public exploit for this vulnerability is currently available, increasing the risk of in-the-wild exploitation. Defenders should restrict access to the web management interface to trusted network segments and monitor for anomalous HTTP traffic directed at the router's web server.

## Impact

Successful exploitation of CVE-2026-105284 grants an attacker full administrative control over the Totolink A3002MU router. This allows for persistent configuration changes, traffic interception, potential credential harvesting, or the redirection of internal network traffic to attacker-controlled infrastructure. The vulnerability is rated with a CVSS 3.1 base score of 10.0, indicating the highest possible severity for impact to confidentiality, integrity, and availability.

## Recommendation

- Restrict access to the router web management interface (typically on port 80 or 443) to trusted internal management subnets via firewall rules or Access Control Lists (ACLs).
- Disable remote web management from the WAN interface immediately to mitigate the risk of internet-based exploitation.
- Implement monitoring on the perimeter or network segment to detect HTTP requests to the A3002MU management interface originating from non-authorized hosts.
- Prioritize the isolation of these devices from the public internet while awaiting a vendor-supplied firmware update.
