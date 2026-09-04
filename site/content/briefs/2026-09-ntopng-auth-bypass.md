---
title: Authorization Bypass in ntopng REST v2 Handlers
slug: 2026-09-ntopng-auth-bypass
description: An authorization bypass vulnerability in ntopng prior to version 6.7.260717 allows authenticated non-administrator users to delete notification endpoints and recipients, disrupting alerting services.
date: "2026-09-04T23:28:05Z"
lastmod: "2026-09-04T23:28:15Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:ntop:ntopng:*:*:*:*:*:*:*:*
tags:
  - web-application
  - authentication-bypass
  - denial-of-service
  - vulnerability
  - authorization-bypass
  - ntopng
vendors:
  - ntop
products:
  - ntopng (< 6.7.260717)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1498
    technique_name: Network Denial of Service
    evidence: Authenticated non-administrator users can issue POST requests to irreversibly delete all configured notification endpoints and recipients, silencing all alerts.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated non-administrator can send a specially crafted POST request to delete all host pools and associated member bindings.
    confidence_band: high
cves:
  - id: CVE-2026-86090
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86090
  - https://nvd.nist.gov/vuln/detail/CVE-2026-86091
rules:
  - title: Detects CVE-2026-86090 Exploitation - Unauthorized REST API Calls in ntopng
    description: Detects potential exploitation of CVE-2026-86090 where a user attempts to access or delete notification endpoints via the ntopng REST v2 API.
    platform: sigma
    severity: high
    tactics:
      - impact
    data_sources:
      - webserver
  - title: Detect CVE-2026-86091 Exploitation - Unauthorized Pool Deletion Attempt
    description: Detects potential exploitation of CVE-2026-86091 by monitoring for POST requests to the pools bulk-delete endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    data_sources:
      - webserver
rules_count: 2
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade ntopng to 6.7.260717 or later.
      owner: IT Operations
      due: 48h
      evidence: NVD vulnerability details regarding patch availability.
  mitigation_plan:
    - priority: immediate
      action: Upgrade ntopng to version 6.7.260717.
      owner: IT Operations
      addresses: CVE-2026-86090
      evidence: Source advisory for CVE-2026-86090.
updates:
  - at: "2026-09-04T23:28:15Z"
    level: L2
    summary: 'added detection rule: Detect CVE-2026-86091 Exploitation - Unauthorized Pool Deletion Attempt'
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-86091
---

The ntopng network traffic analysis tool contains an authorization flaw in the REST v2 API handlers responsible for managing notification endpoints and recipients. Before version 6.7.260717, these delete endpoints fail to verify the administrative privileges of the requesting user. Any user authenticated to the ntopng instance can issue unauthorized POST requests to delete configured notification endpoints and recipients. This action is irreversible and effectively disables the alerting pipeline for the network monitoring system, leading to a denial of service for administrative visibility. Because ntopng is frequently deployed in sensitive network monitoring segments, this vulnerability provides a trivial path for an authenticated attacker with low-privilege access to silence security monitoring and evade detection during subsequent malicious activities.

## Impact

The vulnerability results in a denial of service for the alerting capabilities of ntopng, which may be exploited by an authenticated attacker to mask ongoing unauthorized network activity. All sectors utilizing ntopng for network traffic analysis are affected. Successful exploitation allows for the permanent loss of notification configurations, requiring manual re-configuration by administrators.

## Recommendation

Prioritized actions for detection and mitigation:

- Upgrade all ntopng instances to version 6.7.260717 or later to address CVE-2026-86090.
- Monitor webserver access logs for high-frequency or unauthorized POST requests to REST v2 endpoints related to notification settings.
- Restrict access to the ntopng management interface to authorized administrative segments only.
