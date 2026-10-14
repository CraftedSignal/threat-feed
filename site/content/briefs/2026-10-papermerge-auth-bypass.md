---
title: Missing Authorization Vulnerability in Papermerge Core
slug: 2026-10-papermerge-auth-bypass
description: Papermerge Core versions through 3.5.3 contain a missing authorization vulnerability allowing authenticated users to manipulate or process documents belonging to other users via predictable API endpoints.
date: "2026-10-14T16:37:02Z"
type: advisory
types:
  - advisory
severities:
  - medium
cpes:
  - cpe:2.3:a:papermerge:papermerge_core:*:*:*:*:*:*:*:*
tags:
  - web-application-vulnerability
  - authorization-bypass
  - access-control
vendors:
  - Papermerge
products:
  - Papermerge Core (<= 3.5.3)
cves:
  - id: CVE-2026-110622
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110622
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch Papermerge Core to the version that includes the fix for CVE-2026-110622
      owner: IT Operations
      due: 24h
      evidence: NVD vulnerability disclosure indicates missing authorization in versions up to 3.5.3
  mitigation_plan:
    - priority: immediate
      action: Upgrade Papermerge Core to the latest version
      owner: IT Operations
      addresses: CVE-2026-110622
      evidence: NVD vulnerability details
---

Papermerge Core versions up to and including 3.5.3 are susceptible to a missing authorization vulnerability (CVE-2026-110622). This vulnerability stems from the failure of specific page management and OCR API endpoints to verify the `has_node_perm` permission check for authenticated users. An attacker with a valid low-privileged account can interact with these endpoints by providing the UUIDs of pages owned by other users. Successful exploitation allows unauthorized modification of document structures, including page rotation, deletion, and extraction, as well as the ability to trigger resource-intensive OCR tasks. This flaw poses a significant risk to data integrity and server availability within multi-user Papermerge deployments.

## Impact

Successful exploitation allows authenticated attackers to manipulate or delete documents belonging to other users, potentially leading to unauthorized data destruction or information access. Furthermore, unauthorized triggers of OCR tasks can be used to cause denial-of-service conditions by exhausting server-side processing resources. This vulnerability impacts all installations of Papermerge Core up to version 3.5.3.

## Recommendation

Prioritized actions for administrators of Papermerge Core:

* Apply the security patch provided by the vendor immediately to address CVE-2026-110622.
* Audit access logs for unauthorized HTTP requests to the `/pages/` and `/tasks/` endpoints by users who do not own the associated document UUIDs.
* Limit access to the Papermerge application to trusted users only, as the vulnerability requires an authenticated session to exploit.
