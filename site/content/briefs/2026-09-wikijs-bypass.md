---
title: Access Control Bypass in Wiki.js via Path Prefix Confusion
slug: 2026-09-wikijs-bypass
description: Wiki.js versions 2.5.314 and earlier contain an access control vulnerability where insufficient path validation allows authenticated users to access unauthorized pages sharing a common prefix.
date: "2026-09-16T23:51:58Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wiki_js:wiki_js:*:*:*:*:*:*:*:*
tags:
  - access-control
  - web-application
  - privilege-escalation
vendors:
  - Wiki.js
products:
  - Wiki.js (<= 2.5.314)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Users granted access to a folder can read and modify unrelated pages with matching prefixes, bypassing intended access controls.
    confidence_band: high
cves:
  - id: CVE-2026-92776
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-92776
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  mitigation_plan:
    - priority: immediate
      action: Upgrade Wiki.js to a version later than 2.5.314
      owner: IT Operations
      addresses: CVE-2026-92776
      evidence: NVD vulnerability record for CVE-2026-92776
---

Wiki.js through version 2.5.314 contains an access control bypass vulnerability (CVE-2026-92776) resulting from a flaw in how the application validates START and END page rules. The application fails to strictly require path separators when enforcing these rules, which allows an attacker with legitimate access to a specific folder to inadvertently or maliciously access, read, and modify pages outside their authorized scope, provided those pages share a common name prefix with the authorized folder. This vulnerability can lead to unauthorized information disclosure and modification of wiki content by authenticated users who have been granted restricted access. This is a critical concern for environments relying on Wiki.js for sensitive documentation management where organizational boundaries are enforced through path-based permissions.

## Impact

Successful exploitation allows authenticated users to bypass intended access control lists (ACLs). An attacker could view sensitive documentation or modify pages they are not authorized to access. This primarily affects organizations using Wiki.js to host confidential or internal documentation where fine-grained folder-level permissions are required to segregate user access.

## Recommendation

- Upgrade Wiki.js to a version later than 2.5.314 to ensure proper path separator enforcement in ACL rules.
- Audit existing page permissions and folder structures for overlapping naming conventions that may be susceptible to prefix-based bypasses.
- Review web server access logs for anomalous access patterns where users are accessing documentation paths outside of their assigned organizational units or roles.
