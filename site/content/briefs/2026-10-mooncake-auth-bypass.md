---
title: Authentication Bypass in Mooncake Store
slug: 2026-10-mooncake-auth-bypass
description: Mooncake Store versions through 0.3.13.post1 contain a missing authentication vulnerability in the coro_rpc port, allowing unauthenticated attackers to perform unauthorized deletion operations.
date: "2026-10-06T14:56:21Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:mooncake:mooncake_store:*:*:*:*:*:*:*:*
vendors:
  - Mooncake Store
products:
  - Mooncake Store (<= 0.3.13.post1)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565.002
    technique_name: Data Destruction
    evidence: Attackers can send forged requests with the force flag set to bypass lease checks, wipe keys matching any regex, or clear the entire store, causing cache loss and request failures.
    confidence_band: high
cves:
  - id: CVE-2026-106038
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-106038
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict network access to coro_rpc port
      owner: IT Operations
      due: 24h
      evidence: Vulnerability allows unauthenticated access via coro_rpc port
  mitigation_plan:
    - priority: immediate
      action: Upgrade Mooncake Store to post-0.3.13.post1
      owner: IT Operations
      addresses: CVE-2026-106038
      evidence: Source identifies 0.3.13.post1 as vulnerable
---

Mooncake Store versions up to and including 0.3.13.post1 contain a critical missing authentication vulnerability within its coro_rpc communication component. This flaw permits unauthenticated, remote attackers to interact with internal store management functions. By forging specific requests and setting the force flag, an attacker can bypass intended lease validation mechanisms. This allows for unauthorized execution of administrative operations, specifically the Remove, RemoveByRegex, RemoveAll, and BatchRemove commands. Successful exploitation results in the permanent deletion of arbitrary keys or the complete clearing of the data store, leading to immediate cache loss and sustained service failures for applications relying on the Mooncake Store.

## Impact

Successful exploitation of this vulnerability leads to significant data loss and service disruption for environments utilizing Mooncake Store as a caching layer. Attackers can remotely wipe the entire store or selectively target specific keys, which disrupts application operations and forces a loss of cached state. The CVSS 3.1 base score of 8.2 reflects the high impact on availability and the low complexity of the attack, which requires no authentication to execute.

## Recommendation

Prioritized actions for security and infrastructure teams:
- Update Mooncake Store to a version beyond 0.3.13.post1 immediately upon availability of a patch.
- Implement network-level segmentation to restrict access to the coro_rpc port to trusted internal management hosts only.
- Monitor ingress traffic on the coro_rpc port for anomalous patterns or unexpected requests containing deletion-related commands.
