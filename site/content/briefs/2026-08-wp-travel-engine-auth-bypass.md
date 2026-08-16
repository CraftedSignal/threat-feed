---
title: Authorization Bypass in WP Travel Engine Plugin
slug: 2026-08-wp-travel-engine-auth-bypass
description: An authorization bypass vulnerability in the WP Travel Engine plugin for WordPress allows unauthenticated attackers to exfiltrate customer booking details by manipulating checkout form parameters.
date: "2026-08-16T08:24:52Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - WP Travel Engine
products:
  - WP Travel Engine – Tour Booking Plugin – Tour Operator Software (<= 6.8.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Host Information
    evidence: This makes it possible for unauthenticated attackers to view private booking billing details rendered as default values in checkout form fields by binding an arbitrary booking ID to the attacker's session.
    confidence_band: high
cves:
  - id: CVE-2026-17087
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-17087
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch CVE-2026-17087 by updating the WP Travel Engine plugin to version 6.8.5.
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-17087 affects plugin versions up to and including 6.8.4.
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to latest stable version.
      owner: IT Operations
      addresses: CVE-2026-17087
      evidence: NVD vulnerability disclosure.
---

The WP Travel Engine plugin (up to version 6.8.4) for WordPress contains an authorization bypass vulnerability identified as CVE-2026-17087. This flaw arises because the plugin fails to verify user authorization before serving sensitive booking data. Attackers can exploit this by binding an arbitrary booking ID to their session, which triggers the application to render private customer PII - including names, email addresses, street addresses, and phone numbers - directly into the checkout form's default field values. The endpoint responsible for this data retrieval is inadequately protected by a frontend nonce, which is exposed to all visitors via the global 'wteL10n' variable on trip pages. This exposure renders the nonce ineffective as an access control mechanism, allowing unauthorized entities to perform data exfiltration at scale by iterating through booking identifiers.

## Impact

Successful exploitation results in the unauthorized disclosure of customer PII for users of the WP Travel Engine plugin. This impacts the privacy of customers booking travel services and potentially violates data protection regulations. The scope includes all WordPress sites running versions 6.8.4 or earlier.

## Recommendation

* Update the WP Travel Engine plugin to version 6.8.5 or the latest available release to patch CVE-2026-17087.
* Review web server logs for high volumes of suspicious requests to WordPress checkout or booking endpoints originating from single IP addresses.
* Audit WordPress plugin configurations to ensure unnecessary booking endpoints are restricted or disabled if not actively in use.
