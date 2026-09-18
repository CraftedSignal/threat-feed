---
title: Improper Protocol Downgrade of Extended CONNECT Requests in HTTP/2 and HTTP/3
slug: 2026-09-http-connect-downgrade
description: A vulnerability in HTTP/2 and HTTP/3 protocol handling allows Extended CONNECT requests to be downgraded to regular CONNECT requests, potentially bypassing security policies that rely on Extended CONNECT semantics.
date: "2026-09-18T16:08:31Z"
type: advisory
types:
  - advisory
severities:
  - high
cves:
  - id: CVE-2026-93568
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93568
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review internal proxy and load balancer configurations for policy divergence between CONNECT and Extended CONNECT.
      owner: Detection Engineering
      due: 72h
      evidence: CVE-2026-93568
  mitigation_plan:
    - priority: medium_term
      action: Monitor vendor security bulletins for patches addressing CVE-2026-93568 in network edge components.
      owner: IT Operations
      addresses: CVE-2026-93568
      evidence: CVE-2026-93568
  gaps:
    - Lack of specific vendor software identification for this CVE.
---

CVE-2026-93568 involves a flaw in the handling of HTTP/2 and HTTP/3 protocol features, specifically concerning the Extended CONNECT method. Extended CONNECT is designed to support advanced tunneling and proxying capabilities, often governed by stricter security policies than standard CONNECT requests. Due to this vulnerability, these requests are incorrectly downgraded to regular CONNECT requests by the affected protocol implementations. This behavior allows attackers to circumvent security controls or firewall policies specifically designed to filter, inspect, or block Extended CONNECT traffic. The vulnerability has a CVSS v3.1 base score of 7.5, indicating a high risk to organizations that depend on the semantic distinction between these request types to enforce network security boundaries. Defenders should identify endpoints performing protocol mediation and assess whether existing security rules account for potential downgrade attacks.

## Impact

Successful exploitation could result in the bypass of security policies enforced on tunneling traffic. This may allow unauthorized communication through proxies or firewalls that expect Extended CONNECT semantics, potentially facilitating data exfiltration, C2 traffic, or unauthorized network traversal that would otherwise be blocked or logged under stricter inspection criteria.

## Recommendation

Prioritized, concrete actions for detection engineering teams:
- Audit existing firewall and proxy configurations to determine if security policies for "Extended CONNECT" are distinct from standard "CONNECT" policies.
- Review vendor release notes and security advisories for HTTP/2 and HTTP/3 implementations (e.g., load balancers, proxies, and web server software) to identify if they are impacted by CVE-2026-93568 and apply available patches.
- Monitor logs for unusual instances of standard CONNECT requests originating from clients or segments that typically utilize Extended CONNECT-based protocols.
