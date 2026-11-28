---
brief_id: brief-2026-11-28-windows-dsrm-password-reset
event_id: brief-2026-11-28-windows-dsrm-password-reset
revision: 1
activity_at: "2026-11-28T20:53:13Z"
title: Windows AD DSRM Password Reset
slug: 2026-11-windows-dsrm-password-reset
description: The detection identifies attempts to reset the Directory Services Restore Mode (DSRM) administrator password on a domain controller, a technique used to establish potential persistence.
date: "2026-11-28T20:53:13Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
tags:
  - persistence
  - active-directory
  - endpoint
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: This activity is significant because the DSRM account can be used similarly to a local administrator account, providing potential persistence for an attacker.
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/windows_ad_dsrm_password_reset.yml
  - https://adsecurity.org/?p=1714
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1098/T1098.yaml#L533
rules:
  - title: Windows AD DSRM Password Reset
    description: Detects Event ID 4794, indicating a reset of the DSRM administrator password on a Domain Controller.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098
    data_sources:
      - other
      - windows
      - security
rules_count: 1
---

## Overview
This analytic detects attempts to reset the Directory Services Restore Mode (DSRM) administrator password on a Domain Controller using Windows Security Event Log code 4794. The DSRM account can function like a local administrator account, providing a mechanism for an attacker to maintain administrative access to the Domain Controller.

## Attack Chain
An attacker may attempt to reset the DSRM password to establish long-term persistence on a Domain Controller, effectively bypassing domain-level security policies.

## Impact
Successful exploitation allows an attacker to maintain administrative access to the Domain Controller, posing a severe risk to the security of the Active Directory domain.

## Recommendation
To implement this detection, ensure ingestion of Event ID 4794 and verify that the Advanced Security Audit policy 'Audit User Account Management' within 'Account Management' is enabled on Domain Controllers. Investigate identified password resets to distinguish authorized administrative actions from malicious activity.
