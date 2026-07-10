---
title: Cloud API Calls From Previously Unseen User Roles
slug: 2024-01-unseen-cloud-api
description: This analytic identifies anomalous cloud API calls executed by user roles that have not previously performed those commands, potentially indicating malicious activity or unauthorized actions leading to unauthorized access or data breaches.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - anomaly
  - assumedrole
vendors:
  - Amazon Web Services
products:
  - Amazon Web Services
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1078
    technique_name: Valid Accounts
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://github.com/splunk/security_content/blob/main/detections/cloud/cloud_api_calls_from_previously_unseen_user_roles.yml
rules:
  - title: Detect Cloud API Calls From Previously Unseen User Roles
    description: Detects cloud API calls executed by user roles that have not previously run these commands, indicating potential malicious activity or unauthorized actions.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
  - title: Detect Cloud API Calls From Assumed Role
    description: Detects Cloud API calls executed by an assumed role.
    platform: sigma
    severity: low
    tactics:
      - credential_access
      - defense_evasion
    techniques:
      - T1078
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection analytic identifies anomalous cloud API calls executed by user roles that haven't previously run these commands. The analytic focuses on AWS CloudTrail logs and leverages the Splunk Change data model to identify commands executed by users with the `AssumedRole` user type and successful status. The initial baseline search `Previously Seen Cloud API Calls Per User Role - Initial` is used to establish a baseline of user roles, commands, and their initial timestamps. A secondary baseline search `Previously Seen Cloud API Calls Per User Role - Update` continuously updates the baseline data. The time window for evaluation is configurable through the `cloud_api_calls_from_previously_unseen_user_roles_activity_window` macro.

## Attack Chain

1. An attacker compromises an AWS account or gains access to credentials with `sts:AssumeRole` permissions.
2. The attacker assumes a role, typically one with broader permissions than their initially compromised account. This is logged as an `AssumeRole` event in CloudTrail.
3. The attacker executes a series of API calls using the assumed role.
4. The analytic detects these API calls and compares them against a baseline of previously seen API calls for the specific user role.
5. If an API call is identified as "new" (not present in the baseline or seen within the last 24 hours), the analytic triggers.
6. This "new" API call could be related to reconnaissance, privilege escalation, data exfiltration, or other malicious activities.
7. Successful exploitation can lead to unauthorized access to resources, data breaches, or other detrimental outcomes within the cloud environment.

## Impact

Successful exploitation of new or unmonitored commands within the cloud environment could lead to unauthorized access, data breaches, or other damaging outcomes. Since the ruleset relies on AWS CloudTrail data, the scope of impact is limited to AWS environments. The potential number of affected AWS instances and services varies depending on the permissions of the compromised role and the attacker's objectives.

## Recommendation

*   Ensure AWS CloudTrail logging is enabled and properly configured for all AWS accounts and regions.
*   Implement the baseline searches `Previously Seen Cloud API Calls Per User Role - Initial` and `Previously Seen Cloud API Calls Per User Role - Update` as described in the "How To Implement" section of the analytic.
*   Deploy the analytic "Cloud API Calls From Previously Unseen User Roles" in your Splunk environment.
*   Tune the `cloud_api_calls_from_previously_unseen_user_roles_activity_window` macro based on your environment's specific needs and acceptable thresholds.
*   Customize the `cloud_api_calls_from_previously_unseen_user_roles_filter` macro to exclude known-good API calls and reduce false positives.
