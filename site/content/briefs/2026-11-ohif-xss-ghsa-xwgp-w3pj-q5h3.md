---
brief_id: brief-2026-11-11-ohif-xss-ghsa-xwgp-w3pj-q5h3
event_id: brief-2026-11-11-ohif-xss-ghsa-xwgp-w3pj-q5h3
revision: 1
activity_at: "2026-11-11T11:52:24Z"
title: 'OHIF Viewers: DOM-Based Cross-Site Scripting via DICOM PDF handling (CVE-2026-118670)'
slug: 2026-11-ohif-xss-ghsa-xwgp-w3pj-q5h3
description: A DOM-based XSS vulnerability exists in the OHIF Viewers `dicom-pdf` extension, where unvalidated user-supplied MIME type data in DICOM objects can lead to arbitrary JavaScript execution within the application's origin.
date: "2026-11-11T11:52:24Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
products:
  - '@ohif/extension-dicom-pdf (vulnerable: >= 3.5.0-beta.0, < 3.12.18)'
  - '@ohif/extension-dicom-pdf (vulnerable: >= 3.13.0-beta.0, < 3.13.10)'
  - '@ohif/extension-dicom-pdf (vulnerable: >= 3.14.0-beta.0, < 3.14.0-beta.36)'
cves:
  - id: CVE-2026-118670
    cvss: 8.8
    epss: 0.00421
    kev_status: "false"
references:
  - https://github.com/advisories/GHSA-xwgp-w3pj-q5h3
  - https://github.com/OHIF/Viewers/pull/6228
---

The `dicom-pdf` extension in OHIF Viewers improperly processes the `MIMETypeOfEncapsulatedDocument` (0042,0012) tag from DICOM objects. This value is used to set the `Blob` type when creating a retrieval URL for an encapsulated document. Because the MIME type is not validated, an attacker can specify `text/html`, causing the browser to render the document contents as an HTML page. Since `blob:` URLs inherit the origin of the creating page, any malicious scripts injected into the document bytes will execute with the application's permissions, including access to local storage and session information.
