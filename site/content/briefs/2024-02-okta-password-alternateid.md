---
title: Okta Password Entered in AlternateID Field
slug: 2024-02-okta-password-alternateid
description: Okta logs may contain user passwords if a user mistakenly enters their password into the username field during login, potentially exposing credentials in logs.
date: "2024-02-29T12:00:00Z"
severities:
  - high
tags:
  - attack.credential-access
  - attack.t1552
  - okta
  - password-leak
vendors:
  - Okta
products:
  - Okta Identity Engine
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://developer.okta.com/docs/reference/api/system-log/
  - https://www.mitiga.io/blog/how-okta-passwords-can-be-compromised-uncovering-a-risk-to-user-data
  - https://help.okta.com/en-us/Content/Topics/users-groups-profiles/usgp-create-character-restriction.htm
  - https://github.com/SigmaHQ/sigma/blob/main/rules/identity/okta/okta_password_in_alternateid_field.yml
rules:
  - title: Okta Password Entered in AlternateID Field
    description: Detects when a user has potentially entered their password into the username field, causing the password to be retained in Okta log files.
    platform: sigma
    severity: high
    tactics:
      - credential-access
    techniques:
      - T1552
    data_sources:
      - okta
      - okta
  - title: Okta Password in AlternateID Field - Regex Mismatch
    description: Detects when Okta user login failed, and alternateId look like an email address or Okta service account, meaning that the regex filter is not working properly
    platform: sigma
    severity: medium
    tactics:
      - credential-access
    techniques:
      - T1552
    data_sources:
      - okta
      - okta
rules_count: 2
---

Okta, a leading identity and access management provider, retains login attempt data in its system logs. This data can be valuable for security monitoring and incident response. However, a misconfiguration or user error can lead to sensitive information, such as passwords, being inadvertently captured within these logs. Specifically, if a user mistakenly enters their password in the username field (referred to as 'alternateId' in Okta logs) during a failed login attempt, the password may be…
