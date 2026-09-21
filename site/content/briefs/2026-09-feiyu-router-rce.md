---
title: Command Injection in Chengdu Feiyuxing Technology Feiyu Star Router
slug: 2026-09-feiyu-router-rce
description: An unauthenticated remote command injection vulnerability (CVE-2026-94139) in the Cookie Handler component of Feiyu Star Router allows attackers to execute arbitrary system commands via a manipulated session_id argument.
date: "2026-09-21T06:26:17Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:chengdu_feiyuxing_technology:feiyu_star_router:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - remote-code-execution
  - network-security
vendors:
  - Chengdu Feiyuxing Technology
products:
  - Feiyu Star Router (B-MB5E202-210322-r11656)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: This manipulation of the argument session_id causes command injection.
    confidence_band: high
cves:
  - id: CVE-2026-94139
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94139
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Network Security
  immediate_actions:
    - action: Isolate affected routers from the public internet
      owner: Network Security
      due: 24h
      evidence: Remote exploitation of the attack is possible
  mitigation_plan:
    - priority: immediate
      action: Restrict access to web management endpoint via firewall ACLs
      owner: Network Security
      addresses: CVE-2026-94139
      evidence: Vulnerability reachable via /send_order.cgi
---

A critical command injection vulnerability exists within the Cookie Handler component of the Chengdu Feiyuxing Technology Feiyu Star Router (B-MB5E202-210322-r11656). The flaw resides in the processing logic of the '/send_order.cgi?parameter=loginout' endpoint, specifically failing to sanitize the 'session_id' parameter. An unauthenticated remote attacker can exploit this weakness by injecting shell metacharacters into the 'session_id' argument, leading to arbitrary command execution with the privileges of the web service.

Publicly available exploit code has been identified, increasing the risk of active exploitation. Despite attempts to notify the vendor, no security patches or remediations have been issued. The vulnerability is highly relevant for defenders as it allows for trivial remote code execution on edge network devices, potentially facilitating lateral movement, device takeover, or traffic interception within the target environment. Given the lack of a vendor patch, organizations should consider isolating these devices or restricting access to the management interface.

## Impact

Successful exploitation grants an attacker full remote code execution on the router, which typically acts as a gateway for the network. This provides an entry point for further compromise of internal systems, traffic monitoring, or persistent backdoor installation within the network infrastructure.

## Recommendation

Prioritized actions for security teams:
- Isolate affected Feiyu Star Router units from the public internet immediately to prevent unauthenticated access to '/send_order.cgi'.
- Implement ingress filtering on the perimeter firewall to restrict access to the web management interface of these devices to known, trusted administrative IP addresses.
- Monitor logs for HTTP requests directed at '/send_order.cgi?parameter=loginout' containing shell-sensitive characters (e.g., ;, |, &, $, `) in the session_id parameter.
- Since the vendor has not provided a patch for CVE-2026-94139, evaluate replacement options if the device cannot be adequately secured through network segmentation.
