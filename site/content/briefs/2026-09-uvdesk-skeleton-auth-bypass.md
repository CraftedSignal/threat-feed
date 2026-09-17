---
title: Unauthenticated Administrative Account Creation in UVdesk Community Skeleton
slug: 2026-09-uvdesk-skeleton-auth-bypass
description: A vulnerability in UVdesk Community Skeleton versions through 1.1.8 allows unauthenticated attackers to reconfigure the database and create super administrator accounts via wizard endpoints.
date: "2026-09-16T21:51:47Z"
lastmod: "2026-09-17T18:11:20Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:uvdesk:community_skeleton:*:*:*:*:*:*:*:*
has_poc: true
poc_references:
  - https://sploitus.com/exploit?id=AB910EDC-7848-5F2F-AEA9-EC3D6603C682&utm_source=rss&utm_medium=rss
tags:
  - web-application
  - authentication-bypass
  - critical-vulnerability
vendors:
  - UVdesk
products:
  - Community Skeleton (<= 1.1.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers can repoint the database and create super administrator accounts by submitting crafted requests to wizard endpoints.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1136.002
    technique_name: 'Create Account: Domain Account'
    evidence: Unauthenticated attackers can ... create super administrator accounts by submitting crafted requests.
    confidence_band: high
cves:
  - id: CVE-2026-92805
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92805
  - https://sploitus.com/exploit?id=AB910EDC-7848-5F2F-AEA9-EC3D6603C682&utm_source=rss&utm_medium=rss
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Restrict network access to installation wizard paths for all public-facing UVdesk instances.
      owner: IT Operations
      due: 24h
      evidence: Source confirms vulnerability exists in wizard endpoints.
  mitigation_plan:
    - priority: immediate
      action: Upgrade UVdesk Community Skeleton to a version greater than 1.1.8 once vendor updates are released.
      owner: IT Operations
      addresses: CVE-2026-92805
      evidence: Source identifies vulnerability in versions through 1.1.8.
updates:
  - at: "2026-09-17T18:11:20Z"
    level: L2
    summary: poc_available; added CVE-2026-92805
    sources:
      - sploitus
    source_urls:
      - https://sploitus.com/exploit?id=AB910EDC-7848-5F2F-AEA9-EC3D6603C682&utm_source=rss&utm_medium=rss
---

UVdesk Community Skeleton versions through 1.1.8 contain a critical authentication and validation vulnerability within the ConfigureHelpdesk controller's wizard endpoints. This flaw allows unauthenticated remote attackers to interact with the application installation wizard, which fails to verify whether the system is already configured. By submitting specially crafted HTTP requests to these endpoints, an attacker can redefine the database connection parameters and proceed to register a new super administrator account. This grants the attacker full administrative control over the helpdesk instance, enabling complete data exfiltration, service disruption, or further compromise of the underlying environment. Defenders should treat any unauthorized access to the application's wizard or installation pathways as a critical security incident.

## Impact

Successful exploitation grants an attacker full administrative access to the helpdesk instance. Given the nature of helpdesk platforms, this results in unauthorized access to sensitive customer data, internal communication, and potentially privileged credentials stored within the system. The scale of impact includes complete loss of confidentiality, integrity, and availability for the affected instance.

## Recommendation

- Upgrade UVdesk Community Skeleton to a version beyond 1.1.8 as soon as a patch is available.
- Implement strict network segmentation or Web Application Firewall (WAF) rules to restrict access to installation/wizard routes (e.g., paths associated with ConfigureHelpdesk) to authorized management IPs only.
- Audit existing administrator accounts for anomalous creations or changes following the announcement of this vulnerability.
- Monitor webserver access logs for POST requests targeting wizard or installation configuration endpoints originating from external or unauthorized internal IP addresses.
