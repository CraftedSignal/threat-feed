---
title: AWS Discovery API Calls via CLI from a Single Resource
slug: 2024-11-aws-discovery-api-calls
description: Detection of multiple AWS discovery API calls made via the AWS CLI from a single resource within a 10-second window, potentially indicating reconnaissance attempts by an attacker with compromised credentials or a compromised instance.
date: "2026-04-03T18:54:25Z"
severities:
  - low
tags:
  - cloud
  - aws
  - discovery
  - reconnaissance
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1087
    technique_name: Account Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1526
    technique_name: Cloud Service Discovery
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1580
    technique_name: Cloud Infrastructure Discovery
references:
  - https://stratus-red-team.cloud/attack-techniques/AWS/aws.discovery.ec2-enumerate-from-instance/
  - https://kudelskisecurity.com/research/investigating-two-variants-of-the-trivy-supply-chain-compromise
  - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html
  - https://docs.aws.amazon.com/whitepapers/latest/aws-security-incident-response-guide/aws-security-incident-response-guide.pdf
rules:
  - title: AWS Multiple Discovery API Calls via CLI
    description: Detects multiple AWS discovery API calls via CLI from a single identity within a short timeframe.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
  - title: AWS Discovery API Calls from Unusual Source IP
    description: Detects AWS discovery API calls originating from outside known corporate IP ranges, potentially indicating compromised credentials or external reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1580
    data_sources:
      - cloudtrail
      - aws
rules_count: 2
---

This detection identifies instances where a single AWS resource executes more than five unique discovery-related API calls (Describe*, List*, Get*, or Generate*) within a 10-second window using the AWS CLI. This behavior can indicate an adversary attempting to discover the AWS infrastructure using compromised credentials or a compromised instance. Such reconnaissance is often an early phase of compromise after credential exposure or access to a compromised EC2 instance. The detection excludes…
