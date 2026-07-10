---
title: Okta New Device Enrollment Detection
slug: 2024-01-okta-new-device-enrollment
description: Detection of new device enrollments in Okta, potentially indicating account takeover or unauthorized access by an adversary.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - okta
  - account-takeover
  - persistence
  - cloud
vendors:
  - Okta
products:
  - Okta Identity Cloud
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Access Removal
references:
  - https://attack.mitre.org/techniques/T1098/005/
  - https://developer.okta.com/docs/reference/api/event-types/?q=device.enrollment.create
rules:
  - title: Okta New Device Enrollment
    description: Detects new device enrollments in Okta based on OktaIm2 logs.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - webserver
      - linux
  - title: Okta New Device Enrollment - Data Model
    description: Detects new device enrollments in Okta based on the Change data model.
    platform: sigma
    severity: medium
    tactics:
      - persistence
    techniques:
      - T1098.005
    data_sources:
      - application
      - okta
rules_count: 2
---

This analytic identifies new device enrollments within an Okta environment. By monitoring OktaIm2 logs ingested through the Splunk Add-on for Okta Identity Cloud, security teams can detect the creation of new device enrollments. The creation of new device enrollments could signify a legitimate user adding a new device, but it can also indicate malicious activity, such as an adversary adding a device to maintain unauthorized access to an Okta account. Detecting this behavior is critical for mitigating potential account takeovers, unauthorized access, and persistent control over compromised Okta accounts. This detection is based on the "device.enrollment.create" event type within Okta logs.

## Attack Chain

1.  An attacker gains initial access to an Okta account through compromised credentials, such as via phishing or credential stuffing (not directly covered in the provided source).
2.  The attacker attempts to enroll a new device to the compromised Okta account. This involves initiating a "device.enrollment.create" event.
3.  Okta logs the "device.enrollment.create" event in the OktaIm2 logs. This includes details such as the user, source IP address, and device information (not fully detailed in source).
4.  The attacker completes the device enrollment process, potentially bypassing multi-factor authentication (MFA) if the device is trusted (not directly covered in the provided source).
5.  With the new device enrolled, the attacker can now access Okta-protected resources as if they were the legitimate user.
6.  The attacker uses the new device enrollment to maintain persistence and access the Okta account even if the original compromised credentials are changed.
7.  The attacker leverages this persistent access to steal sensitive data, modify Okta configurations, or pivot to other systems integrated with Okta (not directly covered in the provided source).

## Impact

Successful exploitation can lead to account takeover, where attackers gain complete control over user accounts. This allows them to access sensitive data, modify configurations, and potentially pivot to other systems integrated with Okta. The impact can range from data breaches and financial loss to reputational damage and disruption of services. The number of affected accounts depends on the scope of the attack.

## Recommendation

*   Deploy the provided Sigma rule to your SIEM and tune for your environment to detect new device enrollments in Okta.
*   Investigate any detected new device enrollments, especially those originating from unusual locations or associated with suspicious user activity.
*   Implement multi-factor authentication (MFA) and enforce strong password policies to reduce the risk of initial account compromise (not directly covered in the provided source, but critical).
*   Monitor OktaIm2 logs for any other suspicious activity, such as failed login attempts or changes to user profiles (requires additional Sigma rules and correlation).
*   Review Okta event types to identify other potential indicators of compromise (reference: https://developer.okta.com/docs/reference/api/event-types/?q=device.enrollment.create).
