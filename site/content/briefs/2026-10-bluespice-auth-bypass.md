---
brief_id: brief-2026-10-23-bluespice-auth-bypass
event_id: brief-2026-10-23-bluespice-auth-bypass
revision: 1
activity_at: "2026-10-23T09:35:59Z"
title: 'Hallo Welt! GmbH BlueSpice: Missing Authorization in BlueSpiceUserManager (CVE-2026-25716)'
slug: 2026-10-bluespice-auth-bypass
description: A missing authorization vulnerability in the BlueSpiceUserManager extension allows authenticated users to block or unblock arbitrary accounts, enabling administrative account lockout or unauthorized access restoration.
date: "2026-10-23T09:35:59Z"
lastmod: "2026-10-23T09:36:08Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "5"
  rating: A5
  likelihood: likely
qa_status:
  verdict: pass
cpes:
  - cpe:2.3:a:hallo_welt:bluespice:*:*:*:*:*:*:*:*
  - cpe:2.3:a:hallowelt:bluespice:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - authorization-bypass
  - cloud
  - container-security
vendors:
  - Hallo Welt! GmbH
products:
  - BlueSpice (5.0.0-5.1.10)
  - BlueSpice (5.2.0-5.2.6)
  - BlueSpice (5.2.3 <= version < 5.2.7)
  - BlueSpice (container image bluespice/wiki <= 2026-10-19 15:37 UTC)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This allows locking out all administrators (denial of service) and lifting blocks imposed by administrators.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: This allows locking out all administrators (denial of service).
    confidence_band: high
cves:
  - id: CVE-2026-25716
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-25784
    cvss: 9.8
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25716
  - https://nvd.nist.gov/vuln/detail/CVE-2026-25784
rules:
  - title: Detect CVE-2026-25716 Exploitation - Unauthorized Account Modification
    description: Detects unauthorized attempts to block or unblock users by monitoring API requests to the vulnerable BlueSpiceUserManager endpoints.
    platform: sigma
    severity: high
    tactics:
      - impact
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Upgrade BlueSpice to version 5.1.11 or 5.2.7
      owner: IT Operations
      due: 48h
      evidence: Source states affected versions are before 5.1.11 and 5.2.7.
    - action: Upgrade affected BlueSpice instances to 5.2.7 or replace container images with versions tagged after 2026-10-19 15:37 UTC.
      owner: IT Operations
      due: 48h
      evidence: Source advisory specifies 5.2.7 as the fixed version and 2026-10-19 as the container rebuild date.
  hunt_leads:
    - lead: Analyze access logs for anomalous volume of POST requests to /bs-usermanager/v1/block/ endpoints
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows arbitrary account blocking via specific REST endpoints.
    - lead: Search web access logs for unusual REST API activity involving token authentication requests from unexpected client IP addresses.
      technique_id: T1068
      data_needed:
        - Web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows users to obtain application tokens from the REST API due to disabled IP restrictions.
  mitigation_plan:
    - priority: immediate
      action: Upgrade BlueSpice to 5.1.11 or later
      owner: IT Operations
      addresses: CVE-2026-25716
      evidence: Vendor patch availability.
    - priority: immediate
      action: Set WIKI_SERVICE_TOKEN_AUTH_ALLOWED environment variable to the correct container network CIDR.
      owner: IT Operations
      addresses: CVE-2026-25784
      evidence: Advisory states the vulnerability results from this variable being unset.
updates:
  - at: "2026-10-23T09:36:08Z"
    level: L3
    summary: severity → critical; added CVE-2026-25784
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-25784
---

CVE-2026-25716 is a missing authorization vulnerability in the BlueSpiceUserManager extension for BlueSpice wiki software. The vulnerability exists within the REST endpoints '/bs-usermanager/v1/block/create' and '/bs-usermanager/v1/block/delete'. These endpoints fail to verify if the acting user possesses the required administrative permissions before invoking 'UserManager::blockUser()' or 'UserManager::unblockUser()'. Authenticated users can exploit this to disable any account, including administrators, or reverse existing blocks.

## Impact

Successful exploitation allows for the denial of service (DoS) by locking out administrative users or the circumvention of security controls by lifting administrative blocks on restricted accounts.

## Recommendation

* Inventory instances of BlueSpice running the BlueSpiceUserManager extension.
* Upgrade BlueSpice instances to version 5.1.11 or later for the 5.1.x branch, or 5.2.7 or later for the 5.2.x branch.
* Implement strict monitoring of requests to the '/bs-usermanager/v1/block/' API path to identify unauthorized account modification attempts.
