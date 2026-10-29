---
brief_id: brief-2026-10-29-foxit-ssrf
event_id: brief-2026-10-29-foxit-ssrf
revision: 2
activity_at: "2026-10-29T13:21:48Z"
revision_history:
  - revision: 2
    at: "2026-10-29T13:21:48Z"
    checksum: sha256:cbeeae80fbc0f14ce539e975949323f0807b1bf88261cddf18d334a11f796382
    summary: added CVE-2026-111417
    changed_fields:
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111417
title: 'Foxit HTML-to-PDF Conversion Service: Server-Side Request Forgery (CVE-2026-111418)'
slug: 2026-10-foxit-ssrf
description: A server-side request forgery (SSRF) vulnerability in the Foxit HTML-to-PDF conversion service allows bypass of internal network restrictions via crafted ZIP-formatted input.
date: "2026-10-29T11:14:07Z"
lastmod: "2026-10-29T13:19:52Z"
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
  validation_status: Source corroborated by NVD
cpes:
  - cpe:2.3:a:foxit:html-to-pdf_conversion_service:*:*:*:*:*:*:*:*
  - cpe:2.3:a:foxit:html_to_pdf_conversion_service:*:*:*:*:*:*:*:*
tags:
  - ssrf
  - web-vulnerability
  - cloud
vendors:
  - Foxit
products:
  - HTML-to-PDF conversion service
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A server-side request forgery (SSRF) vulnerability exists in the Foxit official website's HTML-to-PDF conversion service.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1595
    technique_name: Active Scanning
    evidence: Support for ZIP-formatted input can bypass restrictions on requests to internal IP addresses, potentially allowing discovery of internal network resources.
    confidence_band: high
cves:
  - id: CVE-2026-111418
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-111417
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111418
  - https://nvd.nist.gov/vuln/detail/CVE-2026-111417
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review ingress logs for the HTML-to-PDF conversion endpoint for requests containing ZIP-based payloads
      owner: SOC
      due: 24h
      evidence: Service is vulnerable to ZIP-formatted input exploitation
  hunt_leads:
    - lead: Identify internal network requests originating from the HTML-to-PDF conversion service infrastructure
      technique_id: T1190
      data_needed:
        - Server-side egress firewall or proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows bypass of internal network restrictions
  mitigation_plan:
    - priority: immediate
      action: Restrict the HTML-to-PDF service from initiating outbound connections to internal IP ranges (RFC 1918)
      owner: IT Operations
      addresses: CVE-2026-111418
      evidence: Vulnerability allows bypass of restrictions on requests to internal IP addresses
updates:
  - at: "2026-10-29T13:19:52Z"
    level: L2
    summary: added CVE-2026-111417
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-111417
---

A server-side request forgery (SSRF) vulnerability, assigned CVE-2026-111418, exists in the Foxit official website's HTML-to-PDF conversion service. By submitting a ZIP-formatted input file, an attacker can bypass existing restrictions on requests, enabling the service to perform internal network requests. This vulnerability poses a risk of internal resource discovery and potentially unauthorized interaction with services located within the internal network perimeter.

## Impact

Successful exploitation allows for the discovery of internal network resources that are not intended to be exposed to the public internet, potentially leading to unauthorized data access or further internal network reconnaissance.

## Recommendation

1. Monitor web server logs for requests directed at the HTML-to-PDF conversion service containing ZIP archive payloads.
2. Implement strict network egress filtering for the service performing the conversion to ensure it can only reach necessary external endpoints.
3. Validate input types and block ZIP-formatted archives if not strictly required by business workflows until a patch is provided by Foxit.
