---
brief_id: brief-2026-11-13-telerik-vulnerabilities
event_id: brief-2026-11-13-telerik-vulnerabilities
revision: 1
activity_at: "2026-11-13T16:12:52Z"
title: 'Progress Telerik: Multiple vulnerabilities in Document Processing Libraries (CVE-2026-118035, CVE-2026-118036, CVE-2026-118037, CVE-2026-118038, CVE-2026-118039)'
slug: 2026-11-telerik-vulnerabilities
description: Multiple vulnerabilities in Progress Telerik Document Processing Libraries allow remote attackers to cause denial of service, data disclosure, and data integrity compromise via XML external entity injection and path traversal.
date: "2026-11-13T16:12:52Z"
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
  validation_status: All CVEs listed match source
cpes:
  - cpe:2.3:a:progress:telerik_document_processing_libraries:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - xxe
  - path-traversal
  - dos
vendors:
  - Progress
products:
  - Telerik Document Processing Libraries
product_versions:
  - product: Telerik Document Processing Libraries
    range: < 2026.3.1027
cves:
  - id: CVE-2026-118035
    cvss: 7.5
    epss: 0.00292
    kev_status: "false"
  - id: CVE-2026-118036
    kev_status: "false"
  - id: CVE-2026-118037
    kev_status: "false"
  - id: CVE-2026-118038
    cvss: 7.1
    epss: 0.00252
    kev_status: "false"
  - id: CVE-2026-118039
    cvss: 7.5
    epss: 0.00268
    kev_status: "false"
references:
  - https://www.cert.cyber.gouv.fr/avis/CERTFR-2026-AVI-1533/
  - https://www.telerik.com/document-processing-libraries/documentation/knowledge-base/kb-security-xml-external-entity-reference-cve-2026-118039
  - https://www.telerik.com/document-processing-libraries/documentation/knowledge-base/kb-security-path-traversal-cve-2026-118038
  - https://www.telerik.com/document-processing-libraries/documentation/knowledge-base/kb-security-uncontrolled-resource-consumption-spreadprocessing-cve-2026-118037
  - https://www.telerik.com/document-processing-libraries/documentation/knowledge-base/kb-security-uncontrolled-resource-consumption-wordsprocessing-cve-2026-118035
  - https://www.telerik.com/document-processing-libraries/documentation/knowledge-base/kb-security-uncontrolled-resource-consumption-pdfprocessing-cve-2026-118036
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory applications using Telerik Document Processing Libraries
      owner: IT Operations
      due: 48h
      evidence: Source indicates vulnerability exists in libraries prior to 2026.3.1027
  mitigation_plan:
    - priority: immediate
      action: Upgrade Telerik Document Processing Libraries to version 2026.3.1027 or later
      owner: IT Operations
      addresses: CVE-2026-118035, CVE-2026-118036, CVE-2026-118037, CVE-2026-118038, CVE-2026-118039
      evidence: Vendor security bulletins specify version 2026.3.1027 as fixed
---

Progress has released security advisories regarding multiple vulnerabilities in its Telerik Document Processing Libraries affecting versions prior to 2026.3.1027. The vulnerabilities include:

- CVE-2026-118035, CVE-2026-118036, CVE-2026-118037: Uncontrolled resource consumption in Wordsprocessing, PDFprocessing, and Spreadprocessing components leading to denial of service.
- CVE-2026-118038: Path traversal vulnerability.
- CVE-2026-118039: XML external entity (XXE) reference vulnerability.

## Impact
Successful exploitation may result in remote denial of service, unauthorized disclosure of sensitive data, or compromise of data integrity within applications utilizing these libraries.

## Recommendation
Inventory all applications utilizing Progress Telerik Document Processing Libraries and update them to version 2026.3.1027 or later. Refer to the individual vendor security bulletins for specific implementation details.
