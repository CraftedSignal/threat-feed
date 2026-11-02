---
brief_id: brief-2026-11-02-sd-jwt-disclosure-downgrade
event_id: brief-2026-11-02-sd-jwt-disclosure-downgrade
revision: 1
activity_at: "2026-11-02T21:34:13Z"
title: 'SD-JWT JS: Disclosure omission and validation bypass (CVE-2026-62374)'
slug: 2026-11-sd-jwt-disclosure-downgrade
description: The @sd-jwt/decode and @sd-jwt/core libraries (0.19.0) fail to correctly validate SD-JWT disclosures, allowing an attacker to silently drop tampered claims.
date: "2026-11-02T21:34:13Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: not_observed
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
products:
  - '@sd-jwt/decode (<= 0.19.0)'
  - '@sd-jwt/core (<= 0.19.0)'
cves:
  - id: CVE-2026-62374
    epss: 0.00226
    kev_status: "false"
references:
  - https://www.rfc-editor.org/rfc/rfc9901.html
  - https://github.com/advisories/GHSA-f9j6-8p6x-r9j6
---

The `@sd-jwt/decode` and `@sd-jwt/core` libraries (version 0.19.0) contain a validation flaw in the disclosure processing layer that deviates from RFC 9901 requirements. The libraries perform a lossy decoding process that silently drops tampered or non-decodable disclosures instead of rejecting the presentation.

When a disclosure is tampered with (e.g., via byte manipulation or invalid UTF-8 sequences), the library fails to identify the mismatch against the Issuer-signed `_sd` array. Consequently, the library returns a successful verification result containing a reduced claim set. This behavior acts as an omission primitive, potentially allowing holders or on-path attackers to bypass authorization logic that assumes the presence of specific credentials.

The issue specifically violates:
- RFC 9901 §7.1 step 5: Mandatory rejection if any disclosure is not referenced by digest in the signed JWT.
- RFC 9901 §7.1 step 3 / §4.2.1: Mandatory rejection of non-base64url-JSON disclosures.
