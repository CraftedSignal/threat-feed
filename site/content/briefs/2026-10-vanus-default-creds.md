---
title: Unauthenticated Cluster-Admin Access in Vanus via Hardcoded Credentials
slug: 2026-10-vanus-default-creds
description: Vanus versions 0.8.0 through 0.9.0 contain a critical vulnerability allowing unauthenticated remote attackers to gain cluster-admin privileges using a hardcoded default administrative token.
date: "2026-10-18T12:20:55Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:vanus:vanus:0.8.0:*:*:*:*:*:*:*
  - cpe:2.3:a:vanus:vanus:0.9.0:*:*:*:*:*:*:*
tags:
  - vulnerability
  - authentication-bypass
  - cloud-infrastructure
vendors:
  - Vanus
products:
  - Vanus (0.8.0-0.9.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Vanus 0.8.0 through 0.9.0 contains a default credentials vulnerability that allows unauthenticated remote attackers to gain cluster-admin access by using the hardcoded admin token.
    confidence_band: high
cves:
  - id: CVE-2026-111998
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111998
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade all Vanus installations to versions post 0.9.0
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-111998 vulnerability exists in versions 0.8.0 through 0.9.0.
  mitigation_plan:
    - priority: immediate
      action: Restrict access to the Vanus gateway gRPC proxy port via network ACLs
      owner: IT Operations
      addresses: CVE-2026-111998
      evidence: The exploit requires access to the gateway gRPC proxy port.
---

Vanus versions 0.8.0 through 0.9.0 are affected by a critical default credentials vulnerability (CVE-2026-111998). The software ships with a hardcoded administrative Bearer token that is accessible to unauthenticated remote attackers. By supplying this fixed token via the gateway gRPC proxy port, an attacker can authenticate as a cluster administrator. This level of access grants the ability to perform sensitive administrative operations, including the management of namespaces, eventbuses, user accounts, and role bindings. Furthermore, attackers can intercept, read, or publish events within the system, leading to full compromise of the event processing infrastructure. This vulnerability is of high importance to organizations deploying Vanus in production environments, as it allows for trivial remote takeover of the management plane.

## Impact

Successful exploitation grants an unauthenticated attacker full cluster-admin privileges within the Vanus environment. This allows for total control over the event-streaming architecture, including data exfiltration via unauthorized event subscription and the ability to manipulate data flows or system configurations. There are currently no reports of widespread victim impact, but the trivial nature of the exploit poses a high risk to all organizations running affected versions of Vanus.

## Recommendation

- Upgrade all Vanus deployments to a version beyond 0.9.0 that removes the hardcoded credential.
- If immediate patching is not possible, restrict access to the Vanus gateway gRPC proxy port to authorized internal IP addresses only using network access control lists (ACLs).
- Review access logs for the gRPC proxy service for connections using non-standard or suspected default administrative Bearer tokens.
