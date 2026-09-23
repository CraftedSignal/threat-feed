---
title: IDOR Vulnerability in Spree API Associate Endpoint
slug: 2026-09-spree-idor
description: An Insecure Direct Object Reference (IDOR) vulnerability in the Spree API v3 allows authenticated users to associate and exfiltrate PII from arbitrary guest carts using reversible Sqids identifiers.
date: "2026-09-23T01:54:53Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:spreecommerce:spree:*:*:*:*:*:*:*:*
tags:
  - idor
  - broken-access-control
  - spree
  - pii-exposure
vendors:
  - Spree
products:
  - spree_api (5.4.0 - 5.4.3, 5.5.0 - 5.5.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: An authenticated user can supply reversible Sqids-encoded cart IDs to associate arbitrary guest carts with their own account.
    confidence_band: high
cves:
  - id: CVE-2026-94462
    cvss: 7.1
references:
  - https://github.com/advisories/GHSA-4825-p4xm-pcf2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94462
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Patch Spree API to version 5.4.4 or 5.5.4
      owner: IT Operations
      due: 24h
      evidence: Source provides explicit fixed versions for remediation.
  hunt_leads:
    - lead: Multiple PATCH requests to /associate endpoint from a single user session
      technique_id: T1592
      data_needed:
        - Web server access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attacker iterates through derived IDs to exploit the IDOR.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Spree API
      owner: IT Operations
      addresses: CVE-2026-94462
      evidence: Source identifies CVE-2026-94462 as the affected vulnerability.
---

Spree versions 5.4.0 through 5.4.3 and 5.5.0 through 5.5.3 contain a high-severity Insecure Direct Object Reference (IDOR) vulnerability in the `PATCH /api/v3/store/carts/:id/associate` endpoint. The vulnerability arises because the controller fails to perform the standard `authorize!(:update, @cart, cart_token)` check for the association process. Instead, it relies on a `prefixed_id` which is generated via reversible Sqids encoding of sequential database primary keys. An authenticated store user can derive candidate cart IDs offline and iterate through them, associating victim guest carts to their own account. Successful exploitation permits the attacker to read sensitive customer checkout information, including full names, street addresses, and phone numbers stored in the guest cart objects.

## Attack Chain

1. Attacker registers an ordinary customer account on the target Spree storefront.
2. Attacker logs into the store via `POST /api/v3/store/auth/login` to obtain a valid session JWT.
3. Attacker uses the known Sqids algorithm and target sequential database IDs to generate a list of candidate `prefixed_id` strings (e.g., `cart_XXXXXXXXXX`).
4. Attacker iterates through the generated list, sending `PATCH /api/v3/store/carts/:id/associate` requests for each candidate ID.
5. The backend controller processes the request, locates the guest cart via `find_cart_for_association`, and skips the required authorization check.
6. The `Spree.cart_associate_service` reassigns the guest order to the attacker's account and overwrites the associated email address.
7. The API returns a `200 OK` response containing the serialized customer PII (billing and shipping addresses) previously stored on the victim's guest cart.

## Impact

Successful exploitation results in the unauthorized exposure of personally identifiable information (PII) including names, physical addresses, and contact details for store guests. Furthermore, it causes a disruption to the original guest's shopping experience as their in-progress cart is hijacked and reassigned to the attacker's account. This affects any Spree-based storefront not running in `login_required` mode.

## Recommendation

Prioritized actions for administrators:
- Upgrade Spree backend components to version 5.4.4 or 5.5.4 immediately to address CVE-2026-94462.
- Audit access logs for high-frequency `PATCH` requests to the `/api/v3/store/carts/` endpoint originating from single authenticated user sessions.
- Monitor for anomalous `404` or `422` error patterns on the association endpoint which may indicate automated ID enumeration attempts.
