---
title: AWS Identity API Access from Rare ASN Organizations
slug: 2024-01-29-aws-rare-asn
description: This rule detects AWS identities with API traffic dominated by cloud-provider source AS organization labels, but also exhibit traffic from other AS organizations, potentially indicating credential reuse or pivoting.
date: "2024-01-29T12:00:00Z"
severities:
  - high
tags:
  - aws
  - cloudtrail
  - initial-access
  - credential-access
vendors:
  - Amazon
  - Google
  - Microsoft
  - MongoDB
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
references:
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/initial_access_aws_api_unusual_asn.toml
rules:
  - title: AWS API Calls from Unusual ASN
    description: Detects AWS API calls from a source ASN that is not typically associated with the user.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - aws
  - title: AWS Sensitive API Actions from Untrusted ASN
    description: Detects sensitive AWS API actions originating from untrusted ASNs based on the Elastic rule.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1078.004
    data_sources:
      - network_connection
      - aws
rules_count: 2
---

This detection identifies AWS identities that primarily use API traffic originating from well-known cloud providers (e.g., Amazon, Google, Microsoft), but also exhibit a small amount of traffic from less common Autonomous System (AS) organizations. This pattern can indicate that automation or CI credentials are being reused or pivoted outside of their usual hosted cloud environment. The detection focuses on successful API calls and looks for a combination of high volume from trusted cloud…
