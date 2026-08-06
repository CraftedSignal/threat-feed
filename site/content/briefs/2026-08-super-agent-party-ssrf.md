---
title: SSRF Vulnerability in heshengtao super-agent-party
slug: 2026-08-super-agent-party-ssrf
description: A server-side request forgery (SSRF) vulnerability in heshengtao super-agent-party (up to version 0.4.1) allows remote attackers to perform unauthorized requests via the sanitize_proxy_url function.
date: "2026-08-06T01:21:30Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
vendors:
  - heshengtao
products:
  - super-agent-party
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation of the argument url leads to server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-18973
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18973
  - https://vuldb.com/cve/CVE-2026-18973
  - https://gist.github.com/YLChen-007/2f12ffb785d975b46b73896c0fb8cb5d
iocs:
  - type: url
    value: https://gist.github.com/YLChen-007/2f12ffb785d975b46b73896c0fb8cb5d
ioc_counts:
  url: 1
rules:
  - title: Detects CVE-2026-18973 Exploitation - SSRF in extension_proxy
    description: Detects potential SSRF attempts targeting the super-agent-party extension_proxy route by identifying suspicious characters or internal URI patterns in the url argument.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch super-agent-party instances to a secure version.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability identified in versions up to 0.4.1.
  hunt_leads:
    - lead: Search web logs for requests to the /extension_proxy path containing internal IP or protocol schemes.
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows SSRF via the url parameter.
  mitigation_plan:
    - priority: immediate
      action: Implement egress filtering on the host running the proxy service.
      owner: IT Operations
      addresses: CVE-2026-18973
      evidence: SSRF vulnerability allows requests to internal network.
---

A high-severity Server-Side Request Forgery (SSRF) vulnerability (CVE-2026-18973) has been identified in the heshengtao super-agent-party project in versions up to and including 0.4.1. The flaw resides in the `sanitize_proxy_url` function located within the `server.py` file of the `extension_proxy` component. The application fails to properly sanitize the `url` argument, allowing an unauthenticated remote attacker to influence the proxy's request target. This vulnerability can be exploited to force the application server to make arbitrary requests to internal network resources or external services, potentially leading to information disclosure or reconnaissance of internal services inaccessible to the attacker. A public proof-of-concept exploit is available, increasing the risk of active exploitation.

## Attack Chain

1. Attacker performs reconnaissance to identify instances of super-agent-party running in the target environment.
2. Attacker crafts an HTTP request targeting the `extension_proxy` route.
3. Attacker injects a malicious payload into the `url` argument of the request.
4. The `sanitize_proxy_url` function in `server.py` fails to perform adequate input validation on the user-supplied `url`.
5. The server executes an outbound network request to an internal target (e.g., local cloud metadata services or internal APIs) based on the malicious URL.
6. The application processes the response from the internal service and potentially returns the data to the attacker, completing the exfiltration or reconnaissance phase.

## Impact

The vulnerability allows for SSRF, which can be leveraged to bypass network boundaries, access internal services, or query sensitive local cloud metadata endpoints. If the application server has elevated privileges or network access within the internal infrastructure, an attacker could escalate their access or gain further information about the network topology, potentially impacting the confidentiality and integrity of protected systems.

## Recommendation

1. Update heshengtao super-agent-party to the latest available version beyond 0.4.1 that incorporates the fix for CVE-2026-18973.
2. Implement network segmentation and egress filtering on servers running super-agent-party to restrict the proxy's ability to reach sensitive internal subnets or local metadata endpoints (e.g., 169.254.169.254).
3. Deploy web application firewall (WAF) rules to inspect and filter requests targeting the `extension_proxy` path containing suspicious characters or internal URI schemes.
