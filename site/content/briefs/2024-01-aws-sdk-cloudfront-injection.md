---
title: AWS SDK for PHP CloudFront Policy Document Injection via Special Characters
slug: 2024-01-aws-sdk-cloudfront-injection
description: A vulnerability exists in the AWS SDK for PHP CloudFront signing utilities where special characters in input values are not properly handled when creating policy documents, potentially leading to unintended access restrictions, affecting versions 3.11.7 through 3.371.3.
date: "2026-03-27T19:54:58Z"
severities:
  - high
tags:
  - aws
  - cloudfront
  - injection
  - security
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-27qh-8cxx-2cr5
ioc_counts:
  email: 1
rules:
  - title: Detect Suspicious CloudFront URL Parameters with Special Characters
    description: Detects potentially malicious CloudFront URL parameters containing special characters that could indicate policy injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
  - title: Detect Suspicious POST requests to CloudFront URL
    description: Detects potentially malicious POST requests containing special characters in the request body that could indicate policy injection attempts.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
      - linux
rules_count: 2
---

A vulnerability exists in the CloudFront signing utilities within the AWS SDK for PHP, specifically impacting versions 3.11.7 through 3.371.3. These utilities are responsible for generating Amazon CloudFront signed URLs and signed cookies, which control access to content. The vulnerability arises from the improper handling of special characters, such as double quotes and backslashes, within input values used to construct policy documents. If an application passes unsanitized input containing…
