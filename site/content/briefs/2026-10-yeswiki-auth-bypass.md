---
title: YesWiki Triples Delete API Authentication Bypass
slug: 2026-10-yeswiki-auth-bypass
description: An authentication bypass vulnerability in the YesWiki triples delete API allows authenticated users to delete arbitrary semantic triples, potentially resulting in site-wide denial of service.
date: "2026-10-02T12:24:44Z"
lastmod: "2026-10-02T12:27:18Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:yeswiki:yeswiki:*:*:*:*:*:*:*:*
tags:
  - web-application-security
  - authorization-bypass
  - cve-2026-104444
  - web-vulnerability
  - csrf
  - yeswiki
  - sql-injection
  - vulnerability
  - webserver
  - web-application
  - cve
  - ssrf
  - file-upload
  - remote-code-execution
  - exfiltration
vendors:
  - YesWiki
products:
  - YesWiki (< 4.6.7)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An empty-filter scope bypass in the triples delete API that allows any authenticated user to delete or forge arbitrary semantic triples regardless of ownership.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Deleting the admins-group membership triple, emptying the admin group and causing a site-wide authorization lockout.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1529
    technique_name: System Shutdown/Reboot
    evidence: Attackers can lure a logged-in administrator to a crafted link with action=delete and a package parameter to remove extensions like bazar, breaking core site functionality.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers can self-register an account name containing a double-quote payload, then load non-admin ACL-filtered listings to read database contents and bypass read ACLs.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1537
    technique_name: Transfer Data to Cloud Account
    evidence: This lets them inject a five-column UNION subquery to read arbitrary table data such as password hashes.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can import a CSV whose file or image field references a remote .php URL, which is saved without extension checks and executed as server-side code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can import a CSV whose file or image field references a remote .php URL, which is saved without extension checks and executed as server-side code.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Attackers can request the download handler with a known page tag and file parameter to retrieve confidential attachments from read-restricted pages.
    confidence_band: high
cves:
  - id: CVE-2026-104443
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104443
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104444
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104445
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104447
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104456
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104457
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104463
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104471
  - https://nvd.nist.gov/vuln/detail/CVE-2026-104472
rules:
  - title: Detect CVE-2026-104444 Exploitation - Authorization Bypass in YesWiki
    description: Detects unauthorized attempts to edit comments via the YesWiki API by matching patterns indicative of parameter manipulation in the comments route.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
  - title: Detects CVE-2026-104445 Exploitation - Potential ActivityPub Signature Manipulation
    description: Detects potential exploitation of CVE-2026-104445 by identifying ActivityPub 'Delete' or 'Update' actions within web server logs that reference unusual sourceUrl parameters.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
  - title: Detect Exploitation of CVE-2026-104471 - Unauthorized PHP Access in Uploads
    description: Detects potential exploitation attempts of CVE-2026-104471 by monitoring HTTP requests to the 'files/' directory with a .php extension.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade YesWiki to version 4.6.7 or later to patch CVE-2026-104443
      owner: IT Operations
      due: 48h
      evidence: YesWiki before 4.6.7 contains an empty-filter scope bypass
  mitigation_plan:
    - priority: immediate
      action: Upgrade YesWiki to 4.6.7 or later
      owner: IT Operations
      addresses: CVE-2026-104443
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-02T12:25:18Z"
    level: L2
    summary: added coverage for YesWiki (< 4.6.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104456
  - at: "2026-10-02T12:25:24Z"
    level: L2
    summary: added coverage for YesWiki (< 4.6.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104457
  - at: "2026-10-02T12:25:36Z"
    level: L2
    summary: added coverage for YesWiki (< 4.6.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104463
  - at: "2026-10-02T12:27:11Z"
    level: L2
    summary: 'added detection rule: Detect Exploitation of CVE-2026-104471 - Unauthorized PHP Access in Uploads'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104471
  - at: "2026-10-02T12:27:18Z"
    level: L2
    summary: added coverage for YesWiki (< 4.6.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-104472
---

YesWiki versions prior to 4.6.7 are susceptible to an authentication bypass vulnerability residing in the triples delete API. The vulnerability stems from an empty-filter scope bypass, which allows any authenticated user to manipulate or delete semantic triples regardless of defined ownership or permissions. By supplying an empty filter to the triples delete endpoint, an attacker can target critical configuration triples, such as the membership data for the administrative group. Deleting these membership records effectively empties the administrator group, leading to a site-wide administrative lockout. This vulnerability primarily impacts the integrity and availability of YesWiki instances, as unauthorized users can escalate their impact to include a denial of service against the platform administrators.

## Impact

Successful exploitation results in unauthorized modification or deletion of semantic data within the YesWiki application. The most severe consequence is the potential for site-wide administrative lockout, rendering the application unmanageable for legitimate administrators until manual remediation of the affected triples is performed.

## Recommendation

1. Upgrade all YesWiki instances to version 4.6.7 or later to remediate CVE-2026-104443.
2. Audit application logs for anomalous requests to the triples delete API endpoint.
3. Restrict authentication to the YesWiki management interface to trusted users only to reduce the attack surface.
