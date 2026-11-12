---
brief_id: brief-2026-11-12-ivanti-multi-vuln
event_id: brief-2026-11-12-ivanti-multi-vuln
revision: 1
activity_at: "2026-11-12T16:30:50Z"
title: Multiple Vulnerabilities in Ivanti Products
slug: 2026-11-ivanti-multi-vuln
description: Multiple vulnerabilities identified in various Ivanti products may allow for remote code execution, remote denial of service, and risks to data confidentiality and integrity.
date: "2026-11-12T16:30:50Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "1"
  rating: B1
  likelihood: likely
vendors:
  - Ivanti
cves:
  - id: CVE-2026-105425
    kev_status: unknown
  - id: CVE-2026-105669
    kev_status: unknown
  - id: CVE-2026-105813
    kev_status: unknown
  - id: CVE-2026-121683
    kev_status: unknown
  - id: CVE-2026-123179
    kev_status: unknown
  - id: CVE-2026-123181
    kev_status: unknown
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1506/
  - https://forums.ivanti.com/s/article/November-2026-Security-Advisory-Ivanti-EPMM-Multiple-CVEs
  - https://www.ivanti.com/blog/november-2026-security-update
  - https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-CSA-CVE-2026-121683
  - https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-EPM-November-2026
  - https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Sentry-CVE-2026-105425-CVE-2026-105669-CVE-2026-123179-and-CVE-2026-123181
  - https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-User-Workspace-Manager-CVE-2026-105813
---

Multiple vulnerabilities have been discovered in various Ivanti products, as detailed in several security advisories published on November 10, 2026. The identified risks include remote code execution, remote denial of service, SQL injection, and potential impacts on data confidentiality and integrity.

## Impact
Successful exploitation may result in remote code execution, remote denial of service, or compromises to data confidentiality and integrity.

## Recommendation
Refer to the official Ivanti security advisories and the CERT-FR notification for complete details and recommended corrective actions.
