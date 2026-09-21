---
title: Authorization Bypass in NooBaa Multicloud Object Gateway via SigV4
slug: 2026-09-noobaa-sigv4-bypass
description: A signature verification flaw in the noobaa-core component allows attackers to manipulate S3 presigned URLs, leading to unauthorized object copy operations and data access.
date: "2026-09-21T12:28:24Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:redhat:noobaa-core:*:*:*:*:*:*:*:*
vendors:
  - Red Hat
products:
  - noobaa-core
cves:
  - id: CVE-2026-94368
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94368
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch noobaa-core to the remediated version addressing CVE-2026-94368
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-94368 report
  mitigation_plan:
    - priority: immediate
      action: Review access logs for unauthorized CopyObject activity via x-amz-copy-source header
      owner: SOC
      addresses: CVE-2026-94368
      evidence: Source description of vulnerability exploitation
---

A vulnerability (CVE-2026-94368) has been identified in the signature verification logic of the noobaa-core component, which powers the NooBaa Multicloud Object Gateway. The flaw specifically affects how the service processes S3 presigned URLs using the Signature Version 4 (SigV4) protocol. When the gateway receives a request, it improperly handles unsigned x-amz- headers by silently dropping them from the signature calculation process rather than rejecting the request. 

An attacker holding a legitimate presigned PUT URL can exploit this by injecting an unsigned x-amz-copy-source header into the request. Because the server excludes this header from verification, the request remains valid, enabling the attacker to transform a standard upload request into a CopyObject operation. This allows an authenticated attacker to read and copy sensitive data to which the original presigned URL owner has access, potentially exposing objects across the entire storage system managed by the gateway. Defenders should prioritize patching noobaa-core and auditing S3 interaction logs for anomalous usage of copy headers.

## Attack Chain

1. Attacker obtains a legitimate S3 presigned PUT URL for a target bucket managed by NooBaa.
2. Attacker crafts a malicious HTTP request using the presigned URL.
3. Attacker injects an unauthorized 'x-amz-copy-source' header into the request.
4. The noobaa-core component processes the request and calculates the SigV4 signature.
5. The vulnerability in the verification logic ignores the unsigned 'x-amz-copy-source' header during signature validation.
6. The gateway grants the request based on the valid signature of the original PUT request.
7. The system executes the CopyObject operation, allowing the attacker to access and copy unauthorized data.

## Impact

Successful exploitation allows unauthorized access to data within the NooBaa storage environment. By performing unintended CopyObject operations, an attacker can exfiltrate sensitive files or directories to which they would otherwise lack permission, bypassing established authorization controls. This vulnerability impacts all deployments relying on NooBaa Multicloud Object Gateway for S3-compatible storage services.

## Recommendation

* Patch the noobaa-core component to the version that addresses CVE-2026-94368.
* Audit web server and storage gateway access logs for suspicious occurrences of the 'x-amz-copy-source' header in requests that originate from unauthorized or unexpected users.
* Implement strict request validation for S3 SigV4 requests to ensure all headers used for authorization logic are properly verified and non-compliant requests are dropped.
