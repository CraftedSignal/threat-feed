---
title: SeaweedFS Unauthenticated IAM gRPC Service Authentication Bypass
slug: 2026-09-seaweedfs-iam-auth-bypass
description: SeaweedFS versions prior to 4.24 contain an authentication bypass in the IAM gRPC service, allowing unauthenticated network actors to mint administrative S3 credentials and gain full control over object storage via CVE-2026-72920.
date: "2026-09-02T18:03:20Z"
lastmod: "2026-09-03T00:03:19Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:seaweedfs:seaweedfs:*:*:*:*:*:*:*:*
vendors:
  - SeaweedFS
products:
  - SeaweedFS (< 4.24)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any client able to reach the filer gRPC port could invoke IAM RPCs to mint credentials and grant itself S3 administrative privileges.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Any client able to reach the filer gRPC port could invoke IAM RPCs... to mint credentials and grant itself S3 administrative privileges.
    confidence_band: high
cves:
  - id: CVE-2026-72920
    cvss: 9.8
    epss: 0.00408
references:
  - https://github.com/advisories/GHSA-2v6v-25fm-p4fg
  - https://github.com/seaweedfs/seaweedfs/pull/9442
  - https://github.com/advisories/GHSA-gv5w-hfx8-8cwq
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72921
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade SeaweedFS to version 4.24.
      owner: IT Operations
      due: 24h
      evidence: Fixed in 4.24.
    - action: Restrict network access to SeaweedFS gRPC port 8888.
      owner: Security Operations
      due: 24h
      evidence: 'Workarounds: Restrict the filer gRPC port to trusted hosts.'
  mitigation_plan:
    - priority: immediate
      action: Upgrade to 4.24 and configure jwt.filer_signing.key.
      owner: IT Operations
      addresses: CVE-2026-72920
      evidence: 'Patches: Fixed in 4.24.'
updates:
  - at: "2026-09-03T00:03:19Z"
    level: L2
    summary: added coverage for SeaweedFS (< 4.24)
    sources:
      - ghsa
    source_urls:
      - https://github.com/advisories/GHSA-gv5w-hfx8-8cwq
---

SeaweedFS versions prior to 4.24 are vulnerable to an authentication bypass vulnerability (CVE-2026-72920) within the filer IAM gRPC service. The SeaweedIdentityAccessManagement service was registered without authentication requirements, meaning any client with network access to the filer gRPC port could invoke administrative RPC methods such as CreateUser, CreateAccessKey, and PutUserPolicy. This vulnerability persists even if JWT signing keys are configured or if mTLS is in use, as the service lacked specific internal authorization checks. By exploiting this, an attacker can create new administrative users and access keys, granting themselves full read and write control over all S3-compatible object storage managed by the affected filer. This represents a critical risk to data confidentiality, integrity, and availability. Operators must upgrade to version 4.24, which mandates that all IAM RPCs utilize a Bearer token signed by the filer admin signing key.

## Attack Chain

1. Attacker performs network reconnaissance to identify reachable SeaweedFS filer gRPC ports (typically port 8888).
2. Attacker establishes a connection to the gRPC service without providing valid credentials.
3. Attacker calls the SeaweedIdentityAccessManagement CreateUser RPC method to register a new identity.
4. Attacker calls the CreateAccessKey RPC method to generate high-privileged credentials for the new user.
5. Attacker calls the PutUserPolicy RPC method to elevate the new identity to S3 administrator status.
6. Attacker uses the newly minted credentials to authenticate via S3 API calls.
7. Attacker performs unauthorized exfiltration or manipulation of data stored within the SeaweedFS filer.

## Impact

Successful exploitation allows for full administrative compromise of the object storage service. Attackers can gain unrestricted access to the contents of all buckets, modify stored objects, or delete data entirely. This vulnerability affects any deployment where the filer gRPC port is exposed to untrusted network segments, impacting enterprise users relying on SeaweedFS for distributed storage.

## Recommendation

- Upgrade all SeaweedFS instances to version 4.24 immediately to address CVE-2026-72920.
- Apply network-level access control lists (ACLs) to restrict access to the SeaweedFS gRPC port to trusted management subnets only.
- Configure a secure jwt.filer_signing.key in the security.toml file as mandated by the patch to ensure all administrative gRPC operations require valid tokens.
