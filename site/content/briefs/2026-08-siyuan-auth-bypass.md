---
title: Authentication Bypass in SiYuan Publish API
slug: 2026-08-siyuan-auth-bypass
description: SiYuan versions prior to 3.7.4 contain an authentication bypass vulnerability allowing unauthenticated remote attackers to retrieve decrypted content from encrypted notebooks.
date: "2026-08-12T20:54:23Z"
lastmod: "2026-08-12T20:56:35Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - access-control
  - web-vulnerability
  - authentication-bypass
  - information-disclosure
  - api-security
vendors:
  - SiYuan
products:
  - SiYuan
  - SiYuan (< 3.7.4)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Anonymous readers can enumerate and retrieve fully decrypted document content from unlocked encrypted notebooks through the publish API without authentication or key material.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: SiYuan versions before v3.7.4 fail to mask sensitive configuration fields in the /api/system/getConf endpoint, allowing anonymous or publish-reader users to obtain the session-cookie signing key.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers can forge and tamper with session cookies to impersonate users, and on instances without access-auth codes configured, escalate to administrator privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1187
    technique_name: Forced Authentication
    evidence: Attackers can retrieve the CookieKey value and forge valid session cookies to impersonate users or gain administrative access.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can request published blocks containing embed queries to read content from password-protected, hidden, or forbidden documents without authorization.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1592
    technique_name: Gather Victim Org Information
    evidence: Attackers can call these endpoints without supplying a password to read protected document content and the complete reference topology.
    confidence_band: high
cves:
  - id: CVE-2026-72789
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72789
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72793
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72794
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72795
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72801
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72804
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
updates:
  - at: "2026-08-12T20:54:46Z"
    level: L2
    summary: added coverage for SiYuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72793
  - at: "2026-08-12T20:55:08Z"
    level: L2
    summary: added coverage for Siyuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72794
  - at: "2026-08-12T20:55:30Z"
    level: L2
    summary: added coverage for SiYuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72795
  - at: "2026-08-12T20:56:13Z"
    level: L2
    summary: added coverage for SiYuan
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72801
  - at: "2026-08-12T20:56:35Z"
    level: L2
    summary: added coverage for SiYuan (< 3.7.4)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-72804
---

SiYuan versions before 3.7.4 contain a critical authentication bypass vulnerability (CVE-2026-72789) within the application's publish API. The defect stems from an improper access control validation logic where encrypted notebooks are incorrectly treated as publicly accessible by default. When a user has unlocked an encrypted notebook, the application fails to verify the requestor's authorization, enabling anonymous remote users to enumerate and exfiltrate decrypted document content. This flaw allows attackers to bypass intended security boundaries without possessing the necessary encryption keys. Defenders should prioritize updating to v3.7.4 or later to remediate this improper authorization, which significantly exposes sensitive notebook data to unauthorized disclosure.

## Impact

Successful exploitation results in the unauthorized disclosure of sensitive, encrypted document content. Any notebook that has been unlocked by a user becomes vulnerable to retrieval by unauthenticated parties through the publish API. This impacts all SiYuan deployments currently running versions earlier than 3.7.4 that utilize the notebook publishing feature.

## Recommendation

* Update all SiYuan instances to version 3.7.4 or later immediately to patch the access control flaw.
* Audit webserver access logs for high volumes of unexpected GET requests to the publish API endpoints from unauthorized IP addresses.
* Disable the publish API feature temporarily if an immediate update to v3.7.4 is not feasible.
