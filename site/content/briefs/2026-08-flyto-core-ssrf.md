---
title: SSRF Vulnerability in flyto-core via DNS Rebinding
slug: 2026-08-flyto-core-ssrf
description: A Server-Side Request Forgery (SSRF) vulnerability in flyto-core 2.26.7 allows attackers to bypass URL validation via DNS rebinding and interact with internal network resources.
date: "2026-08-17T14:53:28Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - flytohub
products:
  - flyto-core
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A public webapps exploit has been published on Exploit-DB for flyto_core 2.26.7, demonstrating a Server-Side Request Forgery vulnerability.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The guard validates the FIRST resolution (public -> passes) while the CONNECT re-resolves to the sentinel (private) -> internal reach that the guard was supposed to block.
    confidence_band: high
references:
  - https://www.exploit-db.com/exploits/52651
  - https://github.com/Pig-Tail/security-research/tree/master/GHSA-6pm8-6f34-9v3g-flyto-core
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch all instances of flyto-core to version 2.26.8
      owner: IT Operations
      due: 48h
      evidence: Vendor released fixed version 2.26.8
  mitigation_plan:
    - priority: immediate
      action: Restrict egress traffic from web application servers to internal network segments
      owner: Network Security
      addresses: SSRF vulnerability
      evidence: SSRF mitigation best practice
---

Research by Jorge González Milla (Pig-Tail) has identified a critical Server-Side Request Forgery (SSRF) vulnerability in flyto-core versions 2.26.7 and earlier. The flaw resides in the `validate_url_ssrf()` utility function, which performs a DNS resolution to validate the safety of a user-supplied URL. However, the implementation suffers from a time-of-check to time-of-use (TOCTOU) weakness; the application performs an initial DNS check to validate the target's IP address, but then performs a fresh, unpinned DNS resolution when establishing the actual outbound connection. 

By using DNS rebinding with a low TTL (or TTL=0), an attacker can ensure the first resolution returns a public, benign IP address that passes the application's security guard, while the second resolution returns a private, internal IP address (e.g., 127.0.0.1). This allows the application to be coerced into sending requests to internal services or local loopback interfaces that are intended to be shielded from external access. The vulnerability was addressed in version 2.26.8.

## Attack Chain

1. Attacker controls a malicious DNS server capable of responding with different IP addresses for successive lookups of the same domain name (DNS rebinding).
2. Attacker provides a URL pointing to the malicious domain (e.g., `http://rebind.attacker.test/`) to the vulnerable flyto-core application.
3. The `validate_url_ssrf()` function performs an initial DNS resolution for `rebind.attacker.test`.
4. The malicious DNS server returns a public, non-restricted IP address.
5. The `validate_url_ssrf()` function confirms the IP is not in a restricted or private range and allows the request.
6. The application proceeds to establish an outbound connection to the URL, triggering a second DNS resolution for `rebind.attacker.test`.
7. The malicious DNS server returns a restricted internal or loopback IP address (e.g., 127.0.0.1).
8. The application connects to the internal service on the target host, achieving unauthorized SSRF interaction.

## Impact

Successful exploitation of this vulnerability allows unauthorized access to internal network services, private APIs, or local configuration interfaces that are not intended for external reach. In internal or cloud environments, this could lead to the exfiltration of sensitive data, internal service manipulation, or further reconnaissance within the victim's private network infrastructure.

## Recommendation

- Upgrade to flyto-core version 2.26.8 or later immediately to patch the validation logic.
- Implement strict egress filtering on servers running flyto-core to prevent them from initiating outbound connections to internal IP address ranges or sensitive local loopback ports.
- Monitor webserver logs for unusual outbound requests originated by the application logic, particularly those directed toward internal IP ranges.
