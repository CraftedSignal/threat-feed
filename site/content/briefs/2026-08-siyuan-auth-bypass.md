---
title: Authentication Bypass in SiYuan Publish API
slug: 2026-08-siyuan-auth-bypass
description: SiYuan versions prior to 3.7.4 contain an authentication bypass vulnerability allowing unauthenticated remote attackers to retrieve decrypted content from encrypted notebooks.
date: "2026-08-12T20:54:23Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - SiYuan
products:
  - SiYuan
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Anonymous readers can enumerate and retrieve fully decrypted document content from unlocked encrypted notebooks through the publish API without authentication or key material.
    confidence_band: high
cves:
  - id: CVE-2026-72789
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72789
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade SiYuan to version 3.7.4
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-72789 fix identified in v3.7.4
  mitigation_plan:
    - priority: immediate
      action: Disable publish API
      owner: IT Operations
      addresses: CVE-2026-72789
      evidence: Vulnerability exists within the publish API
---

SiYuan versions before 3.7.4 contain a critical authentication bypass vulnerability (CVE-2026-72789) within the application's publish API. The defect stems from an improper access control validation logic where encrypted notebooks are incorrectly treated as publicly accessible by default. When a user has unlocked an encrypted notebook, the application fails to verify the requestor's authorization, enabling anonymous remote users to enumerate and exfiltrate decrypted document content. This flaw allows attackers to bypass intended security boundaries without possessing the necessary encryption keys. Defenders should prioritize updating to v3.7.4 or later to remediate this improper authorization, which significantly exposes sensitive notebook data to unauthorized disclosure.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive, encrypted document content. Any notebook that has been unlocked by a user becomes vulnerable to retrieval by unauthenticated parties through the publish API. This impacts all SiYuan deployments currently running versions earlier than 3.7.4 that utilize the notebook publishing feature.

## Recommendation

* Update all SiYuan instances to version 3.7.4 or later immediately to patch the access control flaw.
* Audit webserver access logs for high volumes of unexpected GET requests to the publish API endpoints from unauthorized IP addresses.
* Disable the publish API feature temporarily if an immediate update to v3.7.4 is not feasible.
