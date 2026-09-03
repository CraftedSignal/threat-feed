---
title: Identity Spoofing Vulnerability in MOOS-IvP uFldNodeComms
slug: 2026-09-moos-ivp-spoofing
description: The uFldNodeComms component in MOOS-IvP versions up to 24.8.1 fails to validate node identity, allowing attackers to spoof packets and inject arbitrary variable notifications.
date: "2026-09-03T23:25:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:moos_ivp:ufldnodecomms:*:*:*:*:*:*:*:*
vendors:
  - MOOS-IvP
products:
  - uFldNodeComms (<= 24.8.1)
cves:
  - id: CVE-2026-85429
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-85429
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade MOOS-IvP uFldNodeComms to a patched version
      owner: IT Operations
      due: 7d
      evidence: CVE-2026-85429
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to uFldNodeComms port via firewall
      owner: Security Engineering
      addresses: CVE-2026-85429
      evidence: Vulnerability allows node impersonation from any connected source.
---

MOOS-IvP is an open-source software project for autonomy, widely used in robotic and marine research applications. The vulnerability, designated CVE-2026-85429, resides in the uFldNodeComms component, which manages communication between different nodes in the autonomy network. In affected versions through 24.8.1, the application fails to verify the authenticity of incoming NODE_MESSAGE packets. Instead of validating the identity against the actual connection source (e.g., verifying the IP address or socket origin), the software trusts the source node identity explicitly defined within the message body.

This flaw allows an attacker capable of communicating with the uFldNodeComms component to craft malicious NODE_MESSAGE packets. By populating the source identity field in the message payload with the name of a legitimate, trusted node, an attacker can impersonate that node. This allows for the injection of arbitrary variable notifications into the MOOS database, enabling unauthorized control, data corruption, or manipulation of the autonomy behaviors controlled by the MOOS-IvP system.

## Impact

Successful exploitation allows for the injection of unauthorized command or state information into the system's database. Given the nature of MOOS-IvP in robotic and autonomous system control, this can result in the subversion of mission-critical behaviors, leading to loss of control, erratic navigation, or data manipulation.

## Recommendation

1. Upgrade all instances of MOOS-IvP to a patched version beyond 24.8.1 once available to address the flawed identity validation logic.
2. Implement network-level segmentation to restrict access to the uFldNodeComms communication port to only known and trusted peer addresses, mitigating the impact of the identity spoofing vulnerability.
3. Inspect firewall logs or network monitoring tools for unauthorized traffic attempting to reach the port utilized by uFldNodeComms from unexpected source IPs.
