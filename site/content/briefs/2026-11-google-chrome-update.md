---
brief_id: brief-2026-11-04-google-chrome-update
event_id: brief-2026-11-04-google-chrome-update
revision: 3
activity_at: "2026-11-10T16:31:37Z"
revision_history:
  - revision: 2
    at: "2026-11-05T10:39:49Z"
    checksum: sha256:1a2dc96599bad019f9b2487d62feb3c8a9e560727e28bbb09d218d3381ec9468
    summary: added CVE-2026-91732
    changed_fields:
      - affected_products
      - cpes
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-91732
  - revision: 3
    at: "2026-11-10T16:31:37Z"
    checksum: sha256:d9d835f81f10f1bd8efadd4ed2dce56aac3e07c42f2e35b2c2bb832315f51027
    summary: new product
    changed_fields:
      - claim_state
      - cves
      - lastmod
      - references
      - updates
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4417
title: 'Google Chrome: Multiple Vulnerabilities'
slug: 2026-11-google-chrome-update
description: Google has released a security update for the Stable Channel of Chrome for Desktop to address unspecified vulnerabilities in versions prior to 157.0.8103.38.
date: "2026-11-04T21:11:46Z"
lastmod: "2026-11-10T16:30:55Z"
type: advisory
claim_state: <nil>
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
  likelihood: roughly even chance
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*
tags:
  - informational
  - browser
  - patch-management
vendors:
  - Google
products:
  - Chrome for Desktop (< 157.0.8103.38)
  - Chrome (< 153.0.8010.47)
affected_os:
  - Windows
  - macOS
  - Linux
cves:
  - id: CVE-2026-91732
    cvss: 8.1
    epss: 0.00261
    kev_status: "false"
references:
  - https://chromereleases.googleblog.com/2026/11/stable-channel-update-for-desktop.html
  - https://cyber.gc.ca/en/alerts-advisories/google-security-advisory-av26-1118
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-91732
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4417
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Update Google Chrome for Desktop to 157.0.8103.38 or higher
      owner: IT Operations
      addresses: Chrome for Desktop versions prior to 157.0.8103.38
      evidence: Source identifies versions prior to 157.0.8103.38/.39 as affected
updates:
  - at: "2026-11-05T10:38:32Z"
    level: L2
    summary: added CVE-2026-91732
    sources:
      - msrc
    source_urls:
      - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-91732
  - at: "2026-11-10T16:30:55Z"
    level: L1
    summary: new product
    sources:
      - bsi
    source_urls:
      - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4417
---

Google has released security updates for the Stable Channel of Chrome for Desktop to address multiple vulnerabilities. The update addresses issues in versions prior to 157.0.8103.38/.39 (Windows/Mac) and 157.0.8103.38 (Linux). Google has not yet disclosed specific vulnerability details, including CVE identifiers, at the time of this report.

## Recommendation

- Update all instances of Google Chrome for Desktop to version 157.0.8103.38 or later for Linux, and 157.0.8103.38/.39 or later for Windows and macOS.
- Inventory systems running Google Chrome to ensure the browser auto-update mechanism is functioning correctly.
