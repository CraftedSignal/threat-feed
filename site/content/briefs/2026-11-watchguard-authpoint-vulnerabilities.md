---
brief_id: brief-2026-11-04-watchguard-authpoint-vulnerabilities
event_id: brief-2026-11-04-watchguard-authpoint-vulnerabilities
revision: 1
activity_at: "2026-11-04T22:03:20Z"
title: WatchGuard AuthPoint Authentication Gateway multiple vulnerabilities (CVE-2026-121637, CVE-2026-121638, CVE-2026-121639, CVE-2026-121640)
slug: 2026-11-watchguard-authpoint-vulnerabilities
description: WatchGuard disclosed four vulnerabilities in AuthPoint Authentication Gateway versions prior to 7.6.0, including flaws enabling forged authentication, man-in-the-middle attacks, denial of service, and unauthorized administrative actions.
date: "2026-11-04T22:03:20Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Confirmed against source documentation; patch versions identified.
cpes:
  - cpe:2.3:a:watchguard:authpoint_authentication_gateway:*:*:*:*:*:*:*:*
vendors:
  - WatchGuard
products:
  - AuthPoint Authentication Gateway (< 7.6.0)
cves:
  - id: CVE-2026-121637
    kev_status: "false"
  - id: CVE-2026-121638
    kev_status: "false"
  - id: CVE-2026-121639
    kev_status: "false"
  - id: CVE-2026-121640
    kev_status: "false"
references:
  - https://cyber.gc.ca/en/alerts-advisories/watchguard-security-advisory-av26-1125
  - https://psirt.watchguard.com/CVE-2026-121637
  - https://psirt.watchguard.com/CVE-2026-121638
  - https://psirt.watchguard.com/CVE-2026-121639
  - https://psirt.watchguard.com/CVE-2026-121640
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  hunt_leads:
    - lead: Monitor AuthPoint logs for anomalous administrative action patterns or unusual LDAP callback authentication results.
      data_needed:
        - AuthPoint management application logs
        - LDAP authentication logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: CVE-2026-121637 and CVE-2026-121640 specifically involve authentication and administrative traffic vectors.
  mitigation_plan:
    - priority: immediate
      action: Upgrade AuthPoint Authentication Gateway to 7.6.0 or later
      owner: IT Operations
      addresses: CVE-2026-121637, CVE-2026-121638, CVE-2026-121639, CVE-2026-121640
      evidence: WatchGuard AuthPoint Authentication Gateway versions prior to 7.6.0 are affected by multiple vulnerabilities.
---

WatchGuard has released security advisories regarding multiple vulnerabilities affecting the AuthPoint Authentication Gateway. Versions prior to 7.6.0 are vulnerable to flaws that could allow attackers to forge authentication results, conduct man-in-the-middle attacks, trigger denial of service, or perform unauthorized administrative actions. As of November 4, 2026, administrators are advised to update to version 7.6.0 or later to mitigate these risks.

## Impact

- CVE-2026-121637: Potential authentication bypass or identity spoofing via HMAC validation failure in LDAP callbacks.
- CVE-2026-121638: Man-in-the-middle (MitM) risk due to improper certificate validation.
- CVE-2026-121639: Unauthenticated denial of service (DoS) via improper authentication handling.
- CVE-2026-121640: Unauthorized administrative control possible through capture-replay of administrative traffic.

## Recommendation

- Upgrade all instances of AuthPoint Authentication Gateway to version 7.6.0 or later immediately.
- Review administrative access logs for anomalous capture-replay signatures or unauthorized administrative configuration changes until patches are applied.
- Restrict network access to the AuthPoint Authentication Gateway management interface to trusted administrative segments to reduce the attack surface for DoS and MitM vectors.
