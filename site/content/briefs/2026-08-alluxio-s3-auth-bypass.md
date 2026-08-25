---
title: Authentication Bypass in Alluxio S3 REST Proxy
slug: 2026-08-alluxio-s3-auth-bypass
description: Alluxio versions 2.9.5 and earlier contain a critical authentication vulnerability that allows unauthenticated attackers to spoof identity and perform unauthorized operations by failing to verify AWS Signature Version 4 requests.
date: "2026-08-25T20:49:15Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - authentication-bypass
  - cve-2026-79787
  - alluxio
vendors:
  - Alluxio
products:
  - alluxio
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Alluxio's S3 REST proxy fails to verify AWS Signature Version 4 signatures in its default configuration, allowing unauthenticated attackers to spoof user identity.
    confidence_band: high
cves:
  - id: CVE-2026-79787
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-79787
  - https://www.vulncheck.com/advisories/alluxio-through-2.9.5-s3-rest-proxy-authentication-bypass-via-unverified-request-signature
  - https://github.com/Alluxio/alluxio/issues/18755
rules:
  - title: Detects CVE-2026-79787 Exploitation - Alluxio S3 Authentication Bypass Attempt
    description: Detects potential exploitation attempts of CVE-2026-79787 where unauthorized or unverified Authorization headers are sent to the Alluxio S3 REST proxy.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review Alluxio footprint and identify instances using S3 REST proxy
      owner: SOC
      due: 24h
      evidence: Critical vulnerability CVE-2026-79787
  mitigation_plan:
    - priority: immediate
      action: Patch Alluxio to latest version
      owner: IT Operations
      addresses: CVE-2026-79787
      evidence: NVD advisory for CVE-2026-79787
---

Alluxio's S3 REST proxy, used in versions 2.9.5 and earlier, is vulnerable to an authentication bypass due to a failure to verify AWS Signature Version 4 (SigV4) signatures in its default configuration. This flaw allows unauthenticated remote attackers to impersonate any user or service account by manipulating the Authorization header. Because the proxy does not validate the integrity or authenticity of the provided credentials, attackers can supply arbitrary usernames to gain unauthorized access to the underlying storage resources. This allows for full read, write, and delete operations on data managed by Alluxio. Given that this component is often used in data platform architectures, the impact of unauthorized data manipulation or exfiltration is severe. Organizations should prioritize updating Alluxio instances to the recommended patched versions once available to prevent unauthorized access.

## Attack Chain

1. Attacker performs reconnaissance on the Alluxio deployment to identify the S3 REST proxy endpoint.
2. Attacker crafts an HTTP request to the target S3 proxy endpoint.
3. Attacker inserts a malformed or arbitrary "Authorization" header containing a target username into the request.
4. The Alluxio S3 REST proxy receives the request and parses the Authorization header.
5. The proxy fails to cryptographically verify the signature associated with the provided identity.
6. The proxy incorrectly authenticates the request based solely on the user-provided identity in the header.
7. The proxy executes the requested data operation (read, write, or delete) with the permissions of the impersonated user.
8. The final objective is reached: unauthorized access, modification, or exfiltration of sensitive data stored within the Alluxio system.

## Impact

Successful exploitation allows unauthenticated remote attackers to gain full administrative control over data managed by the S3 REST proxy. This includes reading sensitive datasets, overwriting or corrupting existing data, and deleting critical information. The vulnerability affects all Alluxio deployments using the default S3 REST proxy configuration up to and including version 2.9.5.

## Recommendation

* Audit all Alluxio deployments to confirm version usage; upgrade to a patched version immediately upon release (CVE-2026-79787).
* Implement strict network access control lists (ACLs) to restrict access to the Alluxio S3 REST proxy endpoint to trusted internal networks only.
* Enable verbose access logging for the S3 REST proxy and alert on any requests containing suspicious or non-standard Authorization headers, as the application logic currently fails to validate them.
* Deploy the Sigma rules in this brief to monitor for unauthorized requests targeting the S3 proxy endpoint (see rule below).
