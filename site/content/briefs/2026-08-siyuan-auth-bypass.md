---
title: Authentication Bypass Vulnerability in SiYuan Publish Mode
slug: 2026-08-siyuan-auth-bypass
description: SiYuan versions before 3.7.3 contain an authentication bypass vulnerability allowing unauthenticated attackers to retrieve content from password-protected documents.
date: "2026-08-03T16:05:17Z"
lastmod: "2026-09-04T00:05:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:siyuan:siyuan:*:*:*:*:*:*:*:*
has_poc: true
vendors:
  - SiYuan
products:
  - SiYuan (< 3.7.3)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: SiYuan versions before v3.7.3 contain an authentication bypass vulnerability in publish mode where content-returning endpoints perform no password check.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Anonymous attackers can retrieve full content of password-protected documents by obtaining internal block IDs.
    confidence_band: high
cves:
  - id: CVE-2026-68584
    cvss: 8.6
    epss: 0.00311
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68584
  - https://github.com/advisories/GHSA-7j72-f6wg-cxw6
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Patch SiYuan software to version 3.7.3 or greater.
      owner: IT Operations
      due: 48h
      evidence: Source explicitly identifies version 3.7.3 as the fix version.
  mitigation_plan:
    - priority: immediate
      action: Disable publish mode if immediate patching is not possible.
      owner: IT Operations
      addresses: CVE-2026-68584
      evidence: Vulnerability is specific to the publish mode implementation.
updates:
  - at: "2026-09-04T00:05:02Z"
    level: L2
    summary: poc_available
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-7j72-f6wg-cxw6
---

SiYuan versions prior to v3.7.3 contain a high-severity authentication bypass vulnerability affecting the software's 'publish mode'. While the primary document access endpoint ('getDoc') correctly implements password verification for protected content, other secondary endpoints - specifically 'getHeadingChildrenDOM', 'getHeadingTransaction', and 'getBacklinkDoc' - fail to perform the necessary authorization checks. 

This vulnerability allows unauthenticated attackers to bypass password gates and exfiltrate the full content of protected documents. Attackers can leverage this by first obtaining internal block IDs from endpoints accessible to readers, and subsequently calling the unprotected endpoints to retrieve the actual sensitive content. Because the application logic relies on these secondary endpoints for metadata and backlink rendering, they are exposed to any visitor of the published site, leading to unauthorized data disclosure. Users are advised to upgrade to version 3.7.3 or later immediately to secure the publish mode infrastructure.

## Impact

Successful exploitation results in the unauthorized exfiltration of sensitive, password-protected document content. Given the nature of SiYuan as a note-taking and knowledge management platform, the impact includes the potential exposure of proprietary research, intellectual property, or personal information hosted within these protected instances. There is no public record of the number of victims, but the vulnerability affects any deployment running an unpatched version of SiYuan with password-protected publishing enabled.

## Recommendation

* Upgrade all instances of SiYuan to version 3.7.3 or later.
* Audit access logs for anomalous, repetitive calls to 'getHeadingChildrenDOM', 'getHeadingTransaction', or 'getBacklinkDoc' from external/unauthenticated source IPs.
* If upgrading is not immediately feasible, disable the publish mode feature to prevent unauthorized access to sensitive document data.
