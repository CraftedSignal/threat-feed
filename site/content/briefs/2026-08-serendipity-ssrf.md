---
title: SSRF Vulnerability in Serendipity serendipity_url_allowed
slug: 2026-08-serendipity-ssrf
description: Serendipity versions prior to 2.6.0 contain a Server-Side Request Forgery vulnerability allowing authenticated admins to reach internal network resources using bypassed address filters.
date: "2026-08-13T12:59:01Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Serendipity
products:
  - Serendipity
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Authenticated users with adminImagesAdd permission can bypass the filter using alternate address formats to request internal services.
    confidence_band: high
cves:
  - id: CVE-2026-73629
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-73629
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Serendipity to version 2.6.0
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-73629 fix is available in Serendipity 2.6.0
  mitigation_plan:
    - priority: immediate
      action: Restrict adminImagesAdd permissions
      owner: IT Operations
      addresses: CVE-2026-73629
      evidence: Exploitation requires authenticated adminImagesAdd permission
---

Serendipity versions prior to 2.6.0 contain a Server-Side Request Forgery (SSRF) vulnerability in the serendipity_url_allowed() function. This filter is intended to validate URLs provided during administrative image uploads, but it fails to properly sanitize or restrict specific address formats. Authenticated users holding the adminImagesAdd permission can leverage this oversight to submit requests to internal network services. By utilizing hex-encoded IPv4 addresses, IPv6 literals, or link-local address ranges, an attacker can bypass existing security controls. Once the server performs the request on behalf of the attacker, the response body can be retrieved and accessed through the public uploads directory, potentially exposing sensitive internal application responses or metadata.

## Impact

Successful exploitation allows authenticated administrators to perform unauthorized requests against internal infrastructure. This can be used to scan internal network segments, interact with non-public services, or exfiltrate sensitive data returned by internal APIs or web services, which is then made accessible through the public uploads directory of the Serendipity installation.

## Recommendation

1. Upgrade all Serendipity instances to version 2.6.0 or higher immediately to apply the patch for CVE-2026-73629.
2. Audit user permissions for the adminImagesAdd role and restrict access to trusted administrators only to minimize the risk of internal exploitation.
3. Monitor web server access logs for unusual outbound requests originating from the Serendipity server, specifically those containing hexadecimal or IPv6-formatted destination addresses.
