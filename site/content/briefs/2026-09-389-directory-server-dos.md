---
title: Denial of Service in 389 Directory Server via CVE-2026-18453
slug: 2026-09-389-directory-server-dos
description: An unauthenticated remote attacker can crash the 389 Directory Server by sending crafted LDAP paged search requests, resulting in a denial of service condition.
date: "2026-09-07T15:33:51Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:389directoryserver:389_directory_server:*:*:*:*:*:*:*:*
products:
  - 389 Directory Server
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote attacker can crash the LDAP server by sending a crafted sequence of search requests using the USE_ONE_BACKEND control, resulting in denial of service.
    confidence_band: high
cves:
  - id: CVE-2026-18453
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-18453
action_plan:
  priority: elevated
  owners:
    - IT Operations
  immediate_actions:
    - action: Upgrade 389 Directory Server to the latest release containing the security patch for CVE-2026-18453.
      owner: IT Operations
      due: 48h
      evidence: Source documentation identifies CVE-2026-18453 as a vulnerability in 389 Directory Server.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to the LDAP port (default 389/636) to authorized management segments.
      owner: Network Security
      addresses: CVE-2026-18453
      evidence: Unauthenticated remote attacker vector.
---

CVE-2026-18453 is a vulnerability in the 389 Directory Server that allows for remote denial of service. The flaw stems from a missing NULL pointer check in the paged results handling logic within the op_shared_search function. An unauthenticated attacker can trigger this condition by sending a specially crafted sequence of LDAP search requests that utilize the USE_ONE_BACKEND control. When the server processes these requests in a specific manner, the lack of input validation results in a NULL pointer dereference, causing the LDAP server process to crash. This vulnerability is significant because it allows remote, unauthenticated actors to disrupt directory services with minimal interaction, potentially impacting authentication and authorization workflows that rely on the directory server.

## Impact

Successful exploitation leads to a denial of service (DoS) of the 389 Directory Server. This impacts organizations relying on the server for centralized identity management, potentially preventing user authentication, service access, and administrative operations. The severity is assessed as high due to the ease of remote execution without authentication requirements.

## Recommendation

* Patch 389 Directory Server to the version containing the fix for CVE-2026-18453.
* Monitor LDAP traffic for excessive or malformed search requests using the USE_ONE_BACKEND control in the request payload.
* Limit network access to the LDAP service to trusted subnets and IP addresses to prevent unauthenticated remote access.
