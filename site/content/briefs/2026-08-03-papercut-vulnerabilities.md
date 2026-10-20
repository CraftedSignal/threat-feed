---
brief_id: brief-2026-08-03-papercut-vulnerabilities
event_id: brief-2026-08-03-papercut-vulnerabilities
revision: 2
activity_at: "2026-08-03T17:58:53Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:fe83bc3f7e05702bfe1ab1e804a35786d2a9e5d2deded6b023af721a552a05d4
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Multiple Vulnerabilities in PaperCut NG/MF
slug: 2026-08-03-papercut-vulnerabilities
description: Multiple vulnerabilities, including CVE-2026-8793 and CVE-2026-8794, affect PaperCut NG/MF versions prior to 26.0.3, potentially allowing for data confidentiality breaches and security policy bypass.
date: "2026-08-03T17:58:53Z"
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
vendors:
  - PaperCut
products:
  - PaperCut NG
  - PaperCut MF
cves:
  - id: CVE-2026-8793
    epss: 0.00683
    kev_status: unknown
  - id: CVE-2026-8794
    epss: 0.00676
    kev_status: unknown
references:
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0959/
  - https://www.papercut.com/kb/Main/papercut-ng-mf-security-bulletin-3-aug-2026/
  - https://www.cve.org/CVERecord?id=CVE-2026-8793
  - https://www.cve.org/CVERecord?id=CVE-2026-8794
---

The French National Cybersecurity Agency (ANSSI) has published an advisory regarding multiple security vulnerabilities identified in PaperCut NG and PaperCut MF. The affected versions are all releases prior to 26.0.3. These vulnerabilities, tracked as CVE-2026-8793 and CVE-2026-8794, present significant risks to organizations by potentially enabling unauthorized parties to access sensitive data and circumvent established security policies within the print management environment. Defenders should prioritize updating instances of PaperCut NG/MF to version 26.0.3 or higher to mitigate these exposures, as outlined in the official vendor security bulletin.

## Impact

Successful exploitation of these vulnerabilities may lead to a breach of data confidentiality and the degradation of security enforcement mechanisms within corporate print management systems. Organizations relying on PaperCut for internal document handling and user authentication are at risk if their software remains unpatched.

## Recommendation

- Upgrade all instances of PaperCut NG and PaperCut MF to version 26.0.3 or later immediately.
- Review the vendor-provided security bulletin (papercut-ng-mf-security-bulletin-3-aug-2026) for specific patch instructions and configuration changes.
- Monitor logs for unusual access patterns to the PaperCut management interface following the patch deployment.
