---
title: 'CVE-2026-111663: SSRF Vulnerability in Chaskiq GraphQL API'
slug: 2026-10-chaskiq-ssrf
description: Chaskiq version 2.0.3 and earlier contains a server-side request forgery vulnerability in the createUrlUpload GraphQL mutation, allowing unauthenticated attackers to access internal resources including cloud metadata services.
date: "2026-10-16T18:49:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:chaskiq:chaskiq:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - graphql
  - web-vulnerability
vendors:
  - Chaskiq
products:
  - Chaskiq (<= 2.0.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated attackers to fetch arbitrary URLs via the createUrlUpload GraphQL mutation.
    confidence_band: high
cves:
  - id: CVE-2026-111663
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111663
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade Chaskiq to a version beyond 2.0.3.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111663 identified as a vulnerability in Chaskiq <= 2.0.3.
  mitigation_plan:
    - priority: immediate
      action: Block egress requests to 169.254.169.254 from the Chaskiq application server.
      owner: IT Operations
      addresses: CVE-2026-111663
      evidence: Source identifies access to cloud instance metadata as a potential impact.
---

Chaskiq versions up to and including 2.0.3 contain a server-side request forgery (SSRF) vulnerability identified as CVE-2026-111663. This flaw resides within the createUrlUpload GraphQL mutation, which improperly validates user-supplied URLs. An unauthenticated attacker can leverage this endpoint to force the Chaskiq server to make arbitrary HTTP requests to internal network resources, including sensitive cloud instance metadata services (e.g., 169.254.169.254). The application processes these requests and subsequently leaks the contents of the response to the attacker via an ActiveStorage blob URL. This vulnerability represents a significant risk for organizations hosting Chaskiq within cloud environments, as it may facilitate the exfiltration of instance identities, security tokens, or internal network mapping.

## Impact

The vulnerability allows unauthenticated attackers to conduct SSRF attacks, potentially leading to unauthorized access to internal network infrastructure or cloud provider service metadata. If exploited, an attacker could extract sensitive configuration data or interact with internal APIs that are not exposed to the public internet, posing a high risk for data breach or deeper network compromise.

## Recommendation

1. Upgrade all instances of Chaskiq to a patched version beyond 2.0.3 immediately to address the vulnerability in the createUrlUpload mutation.
2. Implement network-level egress filtering on the Chaskiq application server to restrict access to internal IP ranges, specifically blocking requests to 169.254.169.254 and other private RFC1918 address spaces.
3. Review web server access logs for anomalous POST requests to the /graphql endpoint containing suspicious URL parameters in the createUrlUpload mutation.
