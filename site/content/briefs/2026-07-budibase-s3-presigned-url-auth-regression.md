---
title: Budibase S3 Presigned URL Authorization Regression
slug: 2026-07-budibase-s3-presigned-url-auth-regression
description: A regression in Budibase v3.39.4 allows BASIC app users to bypass authorization controls and obtain S3 PutObject presigned URLs, enabling low-privileged users to upload arbitrary content to any S3 bucket that the system's stored IAM credentials can access.
date: "2026-07-24T21:20:41Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authorization-bypass
  - privilege-escalation
  - cloud-security
  - s3
  - web-application
vendors:
  - Budibase
products:
  - Budibase (3.39.4)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: In Budibase v3.39.4, a regression in the authorization level for the S3 attachment upload endpoint allows any BASIC app user to obtain S3 PutObject presigned URLs.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1078
    technique_name: ""
    evidence: As a BASIC app user, discover or obtain a valid S3 datasource ID within the app. [...] The response contains a valid S3 PutObject presigned URL.
    confidence_band: high
references:
  - https://github.com/advisories/GHSA-xcx6-4f2g-hhgx
rules:
  - title: Detect Budibase S3 Presigned URL Authorization Bypass Attempt
    description: Detects attempts by potentially low-privileged users to exploit the Budibase v3.39.4 authorization regression to obtain S3 PutObject presigned URLs. This involves POST requests to the /api/attachments/*/url endpoint.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - webserver
rules_count: 1
---

A significant authorization regression in Budibase version 3.39.4 allows any authenticated BASIC app user to generate S3 PutObject presigned URLs. This vulnerability stems from an incorrect permission level assigned to the S3 attachment upload endpoint, which was downgraded from the intended `BUILDER` level to `TABLE/WRITE`. As BASIC users possess `TABLE/WRITE` permissions by default, they can exploit this flaw to obtain valid S3 presigned URLs. Critically, the controller responsible for handling these requests fails to validate the target S3 bucket, meaning an attacker can specify any S3 bucket the underlying IAM credentials have access to, rather than being restricted to the application's configured bucket. This exposes organizations using vulnerable Budibase instances to unauthorized data modification or exfiltration in connected S3 storage. The issue was published in July 2026 and represents a privilege escalation threat impacting cloud environments.

## Attack Chain

1. An attacker, with existing BASIC user credentials for a Budibase application, authenticates to the application.
2. The attacker discovers or obtains a valid S3 datasource ID configured within the Budibase application.
3. The attacker sends a specially crafted HTTP POST request to the `/api/attachments/<datasourceId>/url` endpoint, specifying a target S3 bucket (e.g., `target-bucket`) and a malicious key (e.g., `malicious-file.html`) in the request body.
4. Due to the authorization regression, the Budibase server validates the BASIC user's `TABLE/WRITE` permissions and processes the request.
5. The server responds with a valid S3 PutObject presigned URL that grants temporary write access to the attacker-specified bucket and key.
6. The attacker utilizes the obtained presigned URL to upload arbitrary content (e.g., malware, exfiltrated data) to the designated S3 bucket.
7. The malicious content is successfully uploaded to the S3 bucket, leveraging the compromised IAM credentials of the Budibase instance.

## Impact

The successful exploitation of this vulnerability grants low-privileged BASIC users the ability to perform unauthorized write operations to any S3 bucket accessible by the Budibase application's stored IAM credentials. This can lead to a variety of severe impacts, including data corruption by overwriting legitimate files, data exfiltration by uploading sensitive data to attacker-controlled buckets, or the introduction of malicious content (e.g., web shells, backdoors) if the target bucket serves static web content. The exact number of affected organizations is not specified, but any organization utilizing Budibase v3.39.4 or later unpatched versions with S3 integrations is at risk.

## Recommendation

* Immediately update Budibase installations to a patched version that addresses the CVE and restores the intended authorization logic.
* Deploy the provided Sigma rule to your webserver logs to detect suspicious POST requests to the S3 attachment upload endpoint.
* Monitor cloud audit logs (e.g., AWS CloudTrail) for unusual `s3:PutObject` API calls, especially those initiated by IAM roles associated with Budibase that write to buckets outside of their normal operational scope.
