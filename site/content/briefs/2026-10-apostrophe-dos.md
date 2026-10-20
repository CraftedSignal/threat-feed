---
brief_id: brief-2026-10-20-apostrophe-dos
event_id: brief-2026-10-20-apostrophe-dos
revision: 1
activity_at: "2026-10-20T17:43:43Z"
title: 'ApostropheCMS: Unauthenticated disk exhaustion denial-of-service (CVE-2026-113658)'
slug: 2026-10-apostrophe-dos
description: ApostropheCMS versions prior to 4.33.0 contain a vulnerability in the Rich Text CSV conversion route allowing unauthenticated attackers to trigger disk exhaustion through unmanaged temporary file accumulation.
date: "2026-10-20T17:43:43Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against CVE-2026-113658 details.
cpes:
  - cpe:2.3:a:apostrophecms:apostrophecms:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - web-vulnerability
vendors:
  - ApostropheCMS
products:
  - ApostropheCMS (< 4.33.0)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: Repeated large rejected uploads... can persistently consume temporary-disk capacity and may disrupt ApostropheCMS and other services that depend on the same partition.
    confidence_band: high
cves:
  - id: CVE-2026-113658
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-113658
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade ApostropheCMS to version 4.33.0
      owner: IT Operations
      due: 72h
      evidence: This issue is fixed in version 4.33.0.
  mitigation_plan:
    - priority: immediate
      action: Monitor disk space on volumes hosting system temporary directories.
      owner: IT Operations
      addresses: CVE-2026-113658
      evidence: Repeated large rejected uploads... can persistently consume temporary-disk capacity.
---

ApostropheCMS, an open-source Node.js content management system, contains a vulnerability (CVE-2026-113658) in its Rich Text CSV conversion route. The application fails to properly manage multipart uploads, as it writes incoming files to the system temporary directory before validating file extensions. Critically, the application does not remove these files if the extension validation fails. An unauthenticated attacker can exploit this behavior by repeatedly sending large, specifically crafted, or invalid multipart upload requests while utilizing a valid public CSRF cookie. This process results in the persistent accumulation of files in the temporary directory, which can lead to disk exhaustion. This resource depletion can disrupt the availability of ApostropheCMS and other services residing on the same disk partition. This issue is resolved in version 4.33.0.

## Impact

Successful exploitation results in a denial-of-service condition affecting the host system. By filling the temporary storage partition, an attacker can prevent the target server from performing essential file operations, potentially leading to service crashes or total system failure for all applications sharing the storage partition.

## Recommendation

* Update ApostropheCMS to version 4.33.0 or later to ensure proper cleanup of temporary files during failed upload attempts.
* Monitor system disk space utilization on partitions where the temporary directory (often /tmp or /var/tmp) resides to detect rapid, unauthorized growth indicative of this attack.
* Restrict access to public-facing CSV import or conversion routes at the web application firewall (WAF) level if immediate patching is not possible.
