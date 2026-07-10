---
title: AWS S3 Data Exfiltration via Uncommon Client Applications
slug: 2024-01-02-aws-s3-client-exfiltration
description: This rule detects AWS API activity originating from uncommon desktop client applications based on the user agent string, specifically S3 Browser and Cyberduck, which provide bulk upload/download capabilities and have been observed in use by threat actors for data exfiltration, warranting validation against authorized data transfer workflows.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - aws
  - s3
  - exfiltration
  - cloudtrail
vendors:
  - Amazon
products:
  - Amazon S3
mitre_ttps:
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1567
    technique_name: Exfiltration Over Web Service
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1530
    technique_name: Data from Cloud Storage
references:
  - https://s3browser.com/
  - https://cyberduck.io/
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://attackevals.github.io/ael/enterprise/scattered_spider/emulation_plan/scattered_spider_scenario/
rules:
  - title: AWS API Activity from Uncommon S3 Client
    description: Detects AWS API activity originating from uncommon S3 client applications (S3 Browser, Cyberduck) based on the user agent string.
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
      - linux
  - title: AWS S3 ListBucket from Uncommon Client
    description: Detects AWS S3 ListBucket requests originating from uncommon clients S3 Browser or Cyberduck
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1530
    data_sources:
      - webserver
      - linux
  - title: AWS S3 PutObject from Uncommon Client
    description: Detects AWS S3 PutObject requests originating from uncommon clients S3 Browser or Cyberduck
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
      - linux
rules_count: 3
---

This detection identifies the use of uncommon S3 client applications, specifically S3 Browser and Cyberduck, to interact with AWS S3. While legitimate tools, these applications are rarely used in enterprise environments for authorized data transfer and have been observed being used by threat actors for data exfiltration. The detection focuses on the first-time usage of these clients by a user within an AWS account.  This activity can indicate unauthorized access to sensitive data and potential exfiltration, especially when coupled with unusual source IP addresses or access to sensitive buckets. The rule logic looks for AWS CloudTrail logs with user agent strings matching S3 Browser or Cyberduck where the event outcome was successful.

## Attack Chain

1. An attacker gains unauthorized access to AWS credentials, potentially through credential theft or compromised EC2 instances.
2. The attacker configures S3 Browser or Cyberduck on their local system or a compromised host.
3. The attacker uses the stolen AWS credentials to configure the S3 client application (S3 Browser or Cyberduck).
4. The attacker uses the S3 client to enumerate S3 buckets and identify sensitive data using `ListBucket` operations.
5. The attacker downloads sensitive data from targeted S3 buckets using `GetObject` operations.
6. The attacker stages the data locally or on a compromised system.
7. The attacker uploads the stolen data to an external location or cloud storage using `PutObject` operations, potentially in another AWS account.
8. The attacker attempts to cover their tracks by deleting CloudTrail logs or other evidence, if possible.

## Impact

A successful attack can result in the exfiltration of sensitive data from AWS S3 buckets. The impact includes potential data breaches, financial loss, reputational damage, and regulatory fines. The number of affected users and the value of the compromised data will depend on the scope of the attacker's access and the sensitivity of the data stored in the targeted S3 buckets.

## Recommendation

*   Deploy the Sigma rule `AWS API Activity from Uncommon S3 Client` to your SIEM and tune it for your environment, paying attention to false positives from authorized data migrations (see rule below).
*   Review historical CloudTrail logs for past usage of S3 Browser or Cyberduck to identify any prior unauthorized access.
*   Investigate any identified instances of S3 Browser or Cyberduck usage, focusing on the IAM principal, source network, and accessed buckets.
*   Implement preventive controls such as S3 bucket policies restricting access by user agent or requiring VPC endpoints.
*   Monitor for `CreateAccessKey` events to identify potentially compromised AWS credentials.
*   Enable MFA for all AWS users, especially those with access to sensitive S3 buckets.
