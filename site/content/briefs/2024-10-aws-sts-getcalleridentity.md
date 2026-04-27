---
title: AWS STS GetCallerIdentity API Called for the First Time
slug: 2024-10-aws-sts-getcalleridentity
description: An adversary with access to compromised AWS credentials may attempt to verify their validity and determine the account they are using by calling the STS GetCallerIdentity API, potentially indicating credential compromise and unauthorized discovery activity.
date: "2026-04-10T16:48:32Z"
severities:
  - medium
tags:
  - cloud
  - aws
  - sts
  - discovery
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1033
    technique_name: System Owner/User Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
references:
  - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
  - https://www.secureworks.com/research/detecting-the-use-of-stolen-aws-lambda-credentials
  - https://detectioninthe.cloud/ttps/discovery/sts_get_caller_identity
rules:
  - title: AWS STS GetCallerIdentity API Called for the First Time by New Identity
    description: Detects the first time an identity calls the STS GetCallerIdentity API, potentially indicating compromised credentials.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1033
      - T1087
      - T1087.004
    data_sources:
      - cloudtrail
      - aws
  - title: AWS STS GetCallerIdentity API Called from Unusual Source IP
    description: Detects calls to the GetCallerIdentity API from source IPs that are not typically associated with the user identity.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1033
      - T1087
      - T1087.004
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

The AWS Security Token Service (STS) GetCallerIdentity API allows a user to retrieve information about the IAM user or role associated with the credentials being used. While a legitimate user should already know the account they are operating in, an attacker with compromised credentials may use this API to verify the validity of the credentials and enumerate account details. This activity, especially when observed for the first time from a particular user identity, can indicate malicious…
