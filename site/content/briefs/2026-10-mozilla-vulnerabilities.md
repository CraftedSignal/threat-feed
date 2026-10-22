---
brief_id: brief-2026-10-21-mozilla-vulnerabilities
event_id: brief-2026-10-21-mozilla-vulnerabilities
revision: 2
activity_at: "2026-10-22T07:17:03Z"
revision_history:
  - revision: 2
    at: "2026-10-22T07:17:03Z"
    checksum: sha256:f437bf2917079ee908c2b13a348f61eba141b6903a18142206f4d049be61763d
    summary: Updated cves, priority_score
    changed_fields:
      - cves
      - priority_score
title: Mozilla Firefox and Thunderbird Multiple Vulnerabilities
slug: 2026-10-mozilla-vulnerabilities
description: Multiple vulnerabilities in Mozilla Firefox and Thunderbird, including CVE-2026-113399 through CVE-2026-113869, may lead to arbitrary code execution, data confidentiality compromise, or denial of service.
date: "2026-10-21T16:07:10Z"
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
  validation_status: Needs environment validation
tags:
  - vulnerability
  - browser
  - client-side
vendors:
  - Mozilla
products:
  - Firefox ESR (< 115.43.1)
  - Firefox ESR (< 153.5.1)
  - Firefox (< 158.0.1)
  - Thunderbird (< 153.5.1)
  - Thunderbird (< 158.0.1)
cves:
  - id: CVE-2026-113399
    epss: 0.00179
    kev_status: "false"
  - id: CVE-2026-113400
    kev_status: unknown
  - id: CVE-2026-113401
    kev_status: unknown
  - id: CVE-2026-113470
    kev_status: unknown
  - id: CVE-2026-113866
    cvss: 5.9
    epss: 0.00365
    kev_status: "false"
  - id: CVE-2026-113867
    epss: 0.00179
    kev_status: "false"
  - id: CVE-2026-113868
    cvss: 5.3
    epss: 0.00425
    kev_status: "false"
  - id: CVE-2026-113869
    cvss: 5.4
    epss: 0.00278
    kev_status: "false"
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1346/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-111/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-112/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-113/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-114/
  - https://www.mozilla.org/en-US/security/advisories/mfsa2026-115/
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Firefox and Thunderbird to the latest versions defined in the source (e.g., 158.0.1, 153.5.1, or 115.43.1)
      owner: IT Operations
      addresses: CVE-2026-113399, CVE-2026-113400, CVE-2026-113401, CVE-2026-113470, CVE-2026-113866, CVE-2026-113867, CVE-2026-113868, CVE-2026-113869
      evidence: Source indicates these versions contain necessary patches
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple vulnerabilities affecting various versions of Mozilla Firefox and Thunderbird. These flaws allow for arbitrary code execution, compromise of sensitive data, and denial of service. The vulnerabilities are detailed in Mozilla security advisories MFSA 2026-111 through MFSA 2026-115.

## Impact

Successful exploitation may result in unauthorized arbitrary code execution, loss of data confidentiality, or application-level denial of service.

## Recommendation

- Inventory all enterprise installations of Mozilla Firefox and Thunderbird to identify versions within the affected ranges.
- Upgrade Mozilla Firefox to version 158.0.1 or later.
- Upgrade Mozilla Firefox ESR to version 115.43.1 or 153.5.1 or later as appropriate for the specific release track.
- Upgrade Mozilla Thunderbird to version 153.5.1 or 158.0.1 or later.
- Review the specific Mozilla security advisories (MFSA 2026-111 to MFSA 2026-115) for additional technical context.
