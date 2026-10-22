---
brief_id: brief-2026-10-22-yishaadmin-path-traversal
event_id: brief-2026-10-22-yishaadmin-path-traversal
revision: 1
activity_at: "2026-10-22T14:00:01Z"
title: 'YiShaAdmin: Unauthenticated path traversal (CVE-2022-51022)'
slug: 2026-10-yishaadmin-path-traversal
description: YiShaAdmin versions 2.2 through 3.1 contain an unauthenticated path traversal vulnerability in the DownloadFile endpoint, allowing attackers to read or delete arbitrary files via manipulated parameters.
date: "2026-10-22T14:00:01Z"
type: threat
types:
  - threat
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: very likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:yishaadmin:yishaadmin:2.2:*:*:*:*:*:*:*
  - cpe:2.3:a:yishaadmin:yishaadmin:3.1:*:*:*:*:*:*:*
tags:
  - cve-2022-51022
  - path-traversal
  - web-vulnerability
products:
  - YiShaAdmin (2.2 through 3.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Unauthenticated path traversal in YiShaAdmin /admin/File/DownloadFile allows file access.
    confidence_band: high
cves:
  - id: CVE-2022-51022
    cvss: 9.1
    kev_status: "false"
references:
  - https://huntr.com/bounties/2acdd87a-12bd-4ce4-994b-0081eb908128
  - https://www.vulncheck.com/advisories/yishaadmin-3.1-unauthenticated-path-traversal-via-downloadfile-endpoint
  - https://github.com/liukuo362573/YiShaAdmin/commit/025b0628b1295bd2d9fd6c9b5b82692a345151ef
  - https://sploitus.com/exploit?id=CVE-2022-51022&utm_source=rss&utm_medium=rss
rules:
  - title: Detect CVE-2022-51022 Exploitation - Path Traversal in YiShaAdmin
    description: Detects unauthenticated GET requests to the DownloadFile endpoint containing directory traversal sequences, characteristic of CVE-2022-51022 exploitation.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch YiShaAdmin to the version containing commit 025b062
      owner: IT Operations
      due: 48h
      evidence: Source advisory recommending patch
  mitigation_plan:
    - priority: immediate
      action: Implement WAF blocking for traversal sequences in /admin/File/DownloadFile
      owner: SOC
      addresses: CVE-2022-51022
      evidence: Exploit PoC requires directory traversal strings
---

YiShaAdmin versions 2.2 through 3.1 are vulnerable to unauthenticated path traversal via the /admin/File/DownloadFile endpoint. Attackers can leverage the 'filePath' and 'delete' parameters to read or remove arbitrary files on the underlying system. Exploitation in the wild has been observed since October 2023. This issue is resolved in commit 025b0628b1295bd2d9fd6c9b5b82692a345151ef.

## Impact
Successful exploitation allows unauthenticated remote attackers to access sensitive system files or cause service disruption by deleting arbitrary files.

## Recommendation
- Update YiShaAdmin to the latest version or apply the fix provided in commit 025b0628b1295bd2d9fd6c9b5b82692a345151ef.
- Implement a web application firewall (WAF) rule to inspect requests to /admin/File/DownloadFile for directory traversal sequences (e.g., ../, ..\).
- Deploy the provided Sigma rule to detect exploitation attempts targeting this endpoint.
