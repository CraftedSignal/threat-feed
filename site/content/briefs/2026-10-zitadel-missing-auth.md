---
title: Missing Authentication Vulnerability in ZITADEL Login V1 UI
slug: 2026-10-zitadel-missing-auth
description: An unauthenticated access vulnerability in ZITADEL versions 3.0.0 through 4.17.x allows remote attackers to rename arbitrary user accounts via the change-username handler, resulting in administrative account lockout.
date: "2026-10-12T18:38:27Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:zitadel:zitadel:*:*:*:*:*:*:*:*
vendors:
  - ZITADEL
products:
  - ZITADEL (< 4.18.0)
cves:
  - id: CVE-2026-109371
    cvss: 8.2
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-109371
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade ZITADEL to version 4.18.0 or later
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-109371 patch availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade to ZITADEL 4.18.0
      owner: IT Operations
      addresses: CVE-2026-109371
      evidence: Vendor patch recommendation
---

ZITADEL versions 3.0.0 through 4.17.x are affected by a missing authentication vulnerability located within the hosted Login V1 UI component. The flaw exists in the change-username handler, which processes requests to modify account identifiers without first verifying any authentication factors. By interacting with an active login flow, an unauthenticated attacker can submit a target user's login name followed by a request to update that identifier. This action effectively renames the account, causing a denial of service by locking legitimate users, including administrators, out of their accounts. This vulnerability is significant due to the impact on identity and access management security, potentially allowing an attacker to neutralize administrative control over the ZITADEL instance.

## Impact

Successful exploitation results in unauthorized modification of user identities and account lockout. Organizations using affected ZITADEL deployments face the risk of total loss of administrative access if those accounts are targeted. The vulnerability impacts all ZITADEL instances running versions between 3.0.0 and 4.17.x.

## Recommendation

* Upgrade all ZITADEL deployments to version 4.18.0 or later immediately to patch CVE-2026-109371.
* Audit access logs for unauthorized attempts to invoke the Login V1 UI change-username handler.
* Ensure administrative accounts are managed through secure, hardened identity providers where possible to mitigate the impact of identity-based attacks against the ZITADEL platform.
