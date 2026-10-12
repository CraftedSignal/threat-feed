---
title: Remote Command Injection in TRENDnet Wireless Routers
slug: 2026-10-trendnet-rce
description: An unauthenticated remote command injection vulnerability in the web management backend of legacy TRENDnet routers allows arbitrary OS command execution via manipulated arguments to pigwidgeon.cgi.
date: "2026-10-12T08:08:02Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:h:trendnet:tew-751dr:1.03b01:*:*:*:*:*:*:*
  - cpe:2.3:h:trendnet:tew-751dr:1.03b03:*:*:*:*:*:*:*
  - cpe:2.3:h:trendnet:tew-752dru:1.03b01:*:*:*:*:*:*:*
  - cpe:2.3:h:trendnet:tew-752dru:1.03b03:*:*:*:*:*:*:*
  - cpe:2.3:h:trendnet:tew733gr:1.03b01:*:*:*:*:*:*:*
  - cpe:2.3:h:trendnet:tew733gr:1.03b03:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - command-injection
  - network-infrastructure
  - eol-device
vendors:
  - TRENDnet
products:
  - TEW-751DR (1.03B01/1.03B03)
  - TEW-752DRU (1.03B01/1.03B03)
  - TEW733GR (1.03B01/1.03B03)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: It is possible to launch the attack remotely.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation of the argument service results in os command injection.
    confidence_band: high
cves:
  - id: CVE-2026-108804
    cvss: 10
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108804
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Decommission all TRENDnet TEW-751DR, TEW-752DRU, and TEW733GR hardware.
      owner: IT Operations
      due: 48h
      evidence: Product is EOL; no patches will be provided for CVE-2026-108804.
  mitigation_plan:
    - priority: immediate
      action: Block public-facing access to the management web interface of the affected routers.
      owner: IT Operations
      addresses: CVE-2026-108804
      evidence: Remote exploitation confirmed via pigwidgeon.cgi.
---

A critical command injection vulnerability (CVE-2026-108804) has been identified in the web management backend of legacy TRENDnet router models, including the TEW-751DR, TEW-752DRU, and TEW733GR (versions 1.03B01/1.03B03). The vulnerability resides within the 'fwrite' function of the 'pigwidgeon.cgi' script. By providing a specifically crafted payload to the 'service' argument in an HTTP request, an unauthenticated remote attacker can achieve arbitrary OS command execution with root-level privileges. Since these devices reached end-of-life (EOL) status in 2011, the vendor has confirmed that no security patches will be released. This vulnerability is publicly disclosed and poses a significant risk to any remaining production deployments where these devices have not been decommissioned.

## Impact

The vulnerability allows for unauthenticated remote code execution, effectively granting an attacker full control over the affected network device. Given that these devices are EOL and contain no mechanism for remediation, any unit exposed to the internet is susceptible to immediate compromise. Successful exploitation results in complete system compromise, enabling further lateral movement into the local area network (LAN) attached to the router.

## Recommendation

- Immediately decommission and replace all instances of TRENDnet TEW-751DR, TEW-752DRU, and TEW733GR routers, as they are EOL and cannot be patched.
- Ensure that any remaining legacy network infrastructure is not exposed to the public internet by placing it behind more secure gateway devices or firewalls that can inspect and block malicious HTTP traffic.
- Implement network segmentation to isolate these devices until they are removed from the environment.
- Review perimeter firewall logs for suspicious HTTP requests targeting 'pigwidgeon.cgi' with complex query strings, which may indicate exploitation attempts.
