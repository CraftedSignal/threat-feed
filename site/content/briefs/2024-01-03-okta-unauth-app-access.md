---
title: Okta Unauthorized Access to Application
slug: 2024-01-03-okta-unauth-app-access
description: Anomalous activity indicating a user is attempting to access Okta applications they have not been assigned, potentially leading to data exposure or service disruption.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - okta
  - unauthorized-access
  - identity
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1110
    technique_name: Brute Force
references:
  - https://attack.mitre.org/techniques/T1110/003/
rules:
  - title: Okta Unauthorized Application Access Attempt
    description: Detects attempts by users to access Okta applications they are not authorized to use based on Authentication logs.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - Authentication
      - Okta
  - title: Okta Access Failure From New Country
    description: Alert when an Okta user fails to access an application from a country they have not accessed from before.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1087.004
    data_sources:
      - Authentication
      - Okta
rules_count: 2
---

This analytic identifies attempts by users to access Okta applications to which they have not been assigned. The activity is detected through the analysis of Okta Identity Management logs, specifically focusing on failed access attempts. This behavior is significant because it could indicate unauthorized access attempts, potentially leading to the exposure of sensitive information, data breaches, or disruption of services. While accidental access attempts are possible, repeated or targeted attempts warrant further investigation. The scope of this detection focuses on Okta environments utilizing the Splunk Add-on for Okta Identity Cloud. This alert helps defenders identify potential account compromise or insider threats attempting to access restricted resources.

## Attack Chain

1. User attempts to access an Okta-managed application.
2. Okta evaluates the user's permissions for the requested application.
3. If the user is not assigned the application, Okta logs a failed access attempt.
4. The event is logged in the Okta Identity Management logs (OktaIM2).
5. The logs are ingested into Splunk via the Splunk Add-on for Okta Identity Cloud.
6. The provided analytic identifies the failed access attempt based on the Authentication data model.
7. The analyst investigates the event, looking for patterns of unauthorized access attempts, unusual source IPs, or other suspicious activity.
8. If malicious, the attacker may attempt further exploitation to gain access to sensitive data, such as lateral movement or privilege escalation.

## Impact

Successful exploitation of this vulnerability can lead to unauthorized access to sensitive applications and data within the Okta environment. This can result in data breaches, non-compliance with data protection laws, and overall compromise of the IT environment. The number of affected users and applications depends on the scope of the unauthorized access.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your Okta environment to detect unauthorized application access attempts.
*   Ingest OktaIm2 logs through the Splunk Add-on for Okta Identity Cloud to enable detection (reference in How To Implement).
*   Investigate alerts triggered by the Sigma rule, focusing on the user, source IP, and application accessed.
*   Review Okta application assignment policies and user access rights to minimize the attack surface.
