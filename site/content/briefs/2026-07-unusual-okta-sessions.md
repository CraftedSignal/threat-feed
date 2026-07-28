---
title: Unusual Spike in Concurrent Active Sessions by a User
slug: 2026-07-unusual-okta-sessions
description: An Elastic machine learning rule detects an unusual spike in concurrent active Okta sessions initiated by a user, indicating potential adversary abuse of valid credentials for privilege escalation or persistence through the execution of multiple privileged operations.
date: "2026-07-28T18:15:09Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - okta
  - machine-learning
  - anomaly-detection
  - privilege-escalation
  - persistence
  - cloud-security
vendors:
  - Okta
products:
  - Okta
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A sudden surge in concurrent active sessions by a user may indicate an attempt to abuse valid credentials for privilege escalation
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: Adversaries may exploit valid credentials to initiate multiple sessions, aiming to escalate privileges
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A sudden surge in concurrent active sessions by a user may indicate an attempt to abuse valid credentials for ... maintain persistence.
    confidence_band: high
references:
  - https://www.elastic.co/guide/en/security/current/prebuilt-ml-jobs.html
  - https://docs.elastic.co/en/integrations/pad
---

Elastic has released a machine learning detection rule designed to identify an unusually high number of active concurrent sessions initiated by a single user within an Okta environment. This anomaly can signify potential privileged access abuse by an adversary. The detection leverages Elastic's Anomaly Detection feature to identify sudden surges in concurrent active sessions, which may indicate an attacker is using valid credentials to escalate privileges, maintain persistence, or perform unauthorized actions across different systems simultaneously. This type of activity suggests an adversary has already compromised user credentials and is attempting to maximize their operational impact or evade traditional security controls by distributing their malicious actions across multiple parallel sessions. The rule is part of the Privileged Access Detection (PAD) integration and requires Okta logs to be collected via the Okta integration.

## Impact

Successful exploitation indicated by this anomaly could lead to significant unauthorized access, data exfiltration, or system compromise. An adversary leveraging multiple concurrent sessions can rapidly execute privileged operations, access sensitive resources, or modify configurations across various connected systems within an organization's ecosystem. The primary impact includes privilege escalation and persistence, allowing attackers to solidify their foothold, expand their reach, and perform destructive or espionage activities. The specific number of victims would depend on the targeted user's privileges and the attacker's objectives.

## Recommendation

* Review user activity logs related to the detected anomaly within Okta to identify any unusual patterns, focusing on timestamps, systems accessed, and actions performed during the spike in concurrent sessions.
* Investigate the source IP addresses and geolocations associated with the concurrent sessions in your Okta logs to determine if they align with the user's known locations or indicate unauthorized access.
* Correlate the user's session activity with other security alerts or incidents to assess if this behavior is part of a larger pattern of suspicious activity.
* If malicious activity is confirmed, immediately isolate the user account from the Okta service and affected systems to prevent further unauthorized access or privilege escalation.
* Reset the credentials of the compromised user account and enforce a strong password policy to secure the account.
* Implement additional monitoring on the affected user accounts and systems within Okta to detect any further suspicious activity or attempts to regain access, ensuring the "Unusual Spike in Concurrent Active Sessions by a User" ML job is properly configured.
