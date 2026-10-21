---
brief_id: brief-2026-10-mongodb-bson-recursion
event_id: brief-2026-10-mongodb-bson-recursion
revision: 2
activity_at: "2026-10-21T16:43:21Z"
revision_history:
  - revision: 2
    at: "2026-10-21T16:43:21Z"
    checksum: sha256:b4ae342c67d76a7d33b378872c87d68b741aba6898acee715e086952763f4eac
    summary: added coverage for PHP Driver (< 1.21.12) +2 products
    changed_fields:
      - affected_products
      - cves
      - lastmod
      - references
      - severity
      - updates
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1347/
title: Denial of Service Vulnerability in MongoDB PHP Driver via Uncontrolled Recursion
slug: 2026-10-mongodb-bson-recursion
description: An uncontrolled recursion vulnerability (CVE-2026-112368) in the MongoDB PHP driver allows an unauthenticated attacker to trigger stack exhaustion and process termination by providing malicious BSON documents.
date: "2026-10-19T18:11:38Z"
lastmod: "2026-10-21T16:07:21Z"
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
cpes:
  - cpe:2.3:a:mongodb:php_driver:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - denial-of-service
  - mongodb
vendors:
  - MongoDB
products:
  - MongoDB PHP Driver
  - PHP Driver (< 1.21.12)
  - PHP Driver (2.1.x < 2.1.12)
  - PHP Driver (2.5.x < 2.5.5)
cves:
  - id: CVE-2026-112368
    cvss: 7.5
    kev_status: unknown
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112368
  - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1347/
  - https://jira.mongodb.org/browse/PHPC-276
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Inventory all systems and applications currently utilizing the MongoDB PHP driver to prepare for patching.
      owner: IT Operations
      due: 48h
      evidence: Vulnerability CVE-2026-112368 affects the MongoDB PHP driver.
  mitigation_plan:
    - priority: immediate
      action: Upgrade the MongoDB PHP driver to the patched version once released by MongoDB.
      owner: IT Operations
      addresses: CVE-2026-112368
      evidence: Official NVD advisory regarding CVE-2026-112368.
updates:
  - at: "2026-10-21T16:07:21Z"
    level: L1
    summary: added coverage for PHP Driver (< 1.21.12) +2 products
    sources:
      - anssi
    source_urls:
      - https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-1347/
---

CVE-2026-112368 identifies a critical weakness in the BSON decoding logic within the MongoDB PHP driver. The vulnerability stems from uncontrolled recursion during the parsing process, which can be triggered by an unauthenticated attacker supplying a specially crafted BSON document. Because the failure occurs at the driver level, beneath the PHP execution layer, standard application-level exception or error handling mechanisms are unable to intercept the crash. Successful exploitation results in immediate process termination, leading to a denial-of-service condition for the affected PHP application. This issue is particularly significant for high-traffic web applications that accept user-supplied or external data payloads for MongoDB operations. Defenders should prioritize auditing applications that parse BSON inputs and apply vendor-provided patches as soon as they become available.

## Impact

The impact of this vulnerability is a targeted denial-of-service affecting web applications relying on the MongoDB PHP driver. By causing the PHP process to crash unexpectedly, an attacker can degrade service availability for legitimate users. The inability to catch this error in PHP code means that affected services may require manual intervention or system-level restart logic to recover, potentially causing significant downtime in production environments.

## Recommendation

- Identify all application servers utilizing the MongoDB PHP driver by inspecting dependency manifests (e.g., composer.json) or server environment logs.
- Monitor web server error logs for recurrent sudden process terminations or segmentation faults occurring during BSON decoding operations.
- Apply the vendor-provided patch for CVE-2026-112368 across all affected production and development environments once released by MongoDB.
- Implement input validation and schema enforcement at the application layer to reject unusually deep or malformed BSON documents before they reach the driver level.
