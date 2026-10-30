---
brief_id: brief-2026-10-30-jellyfin-ssrf
event_id: brief-2026-10-30-jellyfin-ssrf
revision: 1
activity_at: "2026-10-30T13:29:45Z"
title: 'Jellyfin: Server-side request forgery in UserImage (CVE-2026-119549)'
slug: 2026-10-jellyfin-ssrf
description: Jellyfin versions up to 12.4 contain an SSRF vulnerability where authenticated users can bypass image validation by submitting gzip-compressed SVG payloads in data URIs to interact with internal network resources or read local files.
date: "2026-10-30T13:29:45Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: needs_environment_validation
cpes:
  - cpe:2.3:a:jellyfin:jellyfin:*:*:*:*:*:*:*:*
tags:
  - web-application
  - ssrf
  - vulnerability
vendors:
  - Jellyfin
products:
  - Jellyfin (<= 12.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can upload such profile images via POST /UserImage, then trigger unauthenticated rendering via GET /UserImage to fetch internal URLs
    confidence_band: high
cves:
  - id: CVE-2026-119549
    cvss: 7.1
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-119549
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all public-facing Jellyfin instances for patch management once a fix is released
      owner: IT Operations
      due: 48h
      evidence: Jellyfin through 12.4 contains a server-side request forgery vulnerability
  hunt_leads:
    - lead: Identify authenticated users posting non-SVG content that may contain encoded data URIs to /UserImage
      technique_id: T1190
      data_needed:
        - Web server access logs or application audit logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: bypass SvgSecurityValidator by embedding gzip-compressed SVG in non-SVG image data URIs
  mitigation_plan:
    - priority: immediate
      action: Upgrade Jellyfin to a version addressing CVE-2026-119549
      owner: IT Operations
      addresses: CVE-2026-119549
      evidence: Jellyfin through 12.4 contains a server-side request forgery vulnerability
---

Jellyfin versions through 12.4 are vulnerable to a Server-Side Request Forgery (SSRF) flaw in the image processing pipeline. An authenticated attacker can bypass the SvgSecurityValidator by embedding gzip-compressed SVG content into non-SVG image data URIs. By uploading a crafted image to the '/UserImage' POST endpoint and triggering a GET request to the same endpoint, the server can be coerced into accessing unauthorized internal network resources or reading local files. The vulnerability can also be leveraged to trigger memory exhaustion on the host system.

## Impact
Successful exploitation allows an authenticated user to perform unauthorized internal network scanning, potentially read local image files on the server, or cause a denial-of-service state through memory exhaustion.

## Recommendation
- Update Jellyfin to a patched version beyond 12.4 once available.
- Until an update is deployed, monitor '/UserImage' endpoints for anomalous POST requests from standard user accounts.
- Restrict access to the Jellyfin instance to trusted networks to mitigate the impact of internal SSRF probes.
