---
title: Denial of Service Vulnerability in MongoDB PHP Driver via Uncontrolled Recursion
slug: 2026-10-mongodb-bson-recursion
description: An uncontrolled recursion vulnerability (CVE-2026-112368) in the MongoDB PHP driver allows an unauthenticated attacker to trigger stack exhaustion and process termination by providing malicious BSON documents.
date: "2026-10-19T18:11:38Z"
type: advisory
types:
  - advisory
severities:
  - low
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
cves:
  - id: CVE-2026-112368
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112368
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
---

CVE-2026-112368 identifies a critical weakness in the BSON decoding logic within the MongoDB PHP driver. The vulnerability stems from uncontrolled recursion during the parsing process, which can be triggered by an unauthenticated attacker supplying a specially crafted BSON document. Because the failure occurs at the driver level, beneath the PHP execution layer, standard application-level exception or error handling mechanisms are unable to intercept the crash. Successful exploitation results in immediate process termination, leading to a denial-of-service condition for the affected PHP application. This issue is particularly significant for high-traffic web applications that accept user-supplied or external data payloads for MongoDB operations. Defenders should prioritize auditing applications that parse BSON inputs and apply vendor-provided patches as soon as they become available.

## Impact

The impact of this vulnerability is a targeted denial-of-service affecting web applications relying on the MongoDB PHP driver. By causing the PHP process to crash unexpectedly, an attacker can degrade service availability for legitimate users. The inability to catch this error in PHP code means that affected services may require manual intervention or system-level restart logic to recover, potentially causing significant downtime in production environments.

## Recommendation

- Identify all application servers utilizing the MongoDB PHP driver by inspecting dependency manifests (e.g., composer.json) or server environment logs.
- Monitor web server error logs for recurrent sudden process terminations or segmentation faults occurring during BSON decoding operations.
- Apply the vendor-provided patch for CVE-2026-112368 across all affected production and development environments once released by MongoDB.
- Implement input validation and schema enforcement at the application layer to reject unusually deep or malformed BSON documents before they reach the driver level.
