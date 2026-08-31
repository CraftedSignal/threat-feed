---
title: Missing Authorization in Kirby CMS REST API Chunked Upload Handler
slug: 2026-08-kirby-unauth-chunk-upload
description: Authenticated users without file upload permissions can exploit a missing authorization check in Kirby CMS to exhaust server storage via incomplete chunked file uploads, leading to denial-of-service.
date: "2026-08-31T23:58:20Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:kirby:cms:*:*:*:*:*:*:*:*
tags:
  - web-application
  - denial-of-service
  - api-security
vendors:
  - Kirby
products:
  - Kirby CMS (>= 5.0.0, < 5.5.2)
cves:
  - id: CVE-2026-71415
references:
  - https://github.com/advisories/GHSA-67mx-6wf2-92xp
  - https://github.com/getkirby/kirby/releases/tag/5.5.2
  - https://nvd.nist.gov/vuln/detail/CVE-2026-71415
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Kirby CMS to 5.5.2 or later.
      owner: IT Operations
      due: 24h
      evidence: 'Source states: The problem has been patched in Kirby 5.5.2.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade to Kirby 5.5.2 or later.
      owner: IT Operations
      addresses: CVE-2026-71415
      evidence: 'Source states: The problem has been patched in Kirby 5.5.2.'
---

Kirby CMS versions 5.0.0 through 5.5.1 are vulnerable to a missing authorization flaw (CVE-2026-71415) within the REST API chunked file upload handler. An authenticated user, even one explicitly denied 'files.create', 'files.replace', or 'user/users.update' permissions, can initiate a chunked upload process. The application fails to validate these permissions before writing incoming file chunks to a temporary directory on the server.

This flaw allows an attacker to repeatedly upload large files in chunks without ever completing the final assembly. Because the application retains these incomplete files in the temporary directory for 24 hours, an attacker can intentionally saturate available disk space. This activity causes a denial-of-service condition, preventing legitimate users from performing authorized file uploads or potentially disrupting other site functions that rely on server storage availability.

## Impact

The vulnerability allows authenticated attackers to perform a resource exhaustion attack against server storage. Success results in potential service interruption for legitimate file operations. While the exploit does not bypass final permission checks for data moved to the 'content' or 'site/accounts' directories, the ability to consume disk space at will represents a high-severity availability risk for impacted sites.

## Recommendation

Prioritized actions for administrators:

* Patch Kirby CMS immediately by upgrading to version 5.5.2 or later to include the mandatory preflight permission checks.
* Monitor web server logs for high volumes of POST requests to REST API upload routes originating from accounts identified as having restricted file upload permissions.
* Review disk usage monitoring metrics to identify spikes in temporary file storage that may indicate active exploitation attempts.
