---
title: awslabs/tough Missing Delegated Metadata Validation
slug: 2024-01-tough-metadata-validation
description: The tough library before version 0.22.0 and tuftool before version 0.15.0 do not properly verify delegated target metadata, allowing an attacker with write access to serve expired or otherwise invalid targets from a TUF repository, potentially leading to the library trusting invalid targets.
date: "2026-05-05T18:46:48Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - vulnerability
  - metadata-poisoning
vendors:
  - Amazon
  - Amazon Web Services Labs
products:
  - tough
  - tuftool
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1565
    technique_name: Data Manipulation
cves:
  - id: CVE-2026-6967
    cvss: 5.9
    epss: 0.00027
references:
  - https://github.com/advisories/GHSA-4v58-8p28-2rq3
  - CVE-2026-6967
iocs:
  - type: email
    value: aws-security@amazon.com
ioc_counts:
  email: 1
rules:
  - title: Detect Process Accessing Metadata Files with Unusual Hashes
    description: Detects processes accessing TUF metadata files with unusual or suspicious hash values, potentially indicating a metadata poisoning attack.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1565.001
    data_sources:
      - file_event
      - windows
  - title: Detect Unexpected File Downloads in TUF Metadata Directory
    description: Detects new file creations within the TUF metadata directory, which may indicate a malicious actor attempting to modify or inject malicious metadata.
    platform: sigma
    severity: medium
    tactics:
      - integrity
    techniques:
      - T1565.001
    data_sources:
      - file_event
      - windows
rules_count: 2
---

The `awslabs/tough` library, a Python implementation of The Update Framework (TUF), is vulnerable to a metadata validation bypass. Specifically, versions prior to 0.22.0 and tuftool versions prior to 0.15.0 do not properly enforce expiration, hash, and length checks on delegated metadata. An attacker with delegated signing authority can exploit this vulnerability to poison the local metadata cache. This occurs because the `load_delegations` function doesn't apply the same strict validation checks as the top-level targets metadata path. Successful exploitation allows the attacker to serve expired or otherwise invalid targets from a TUF repository, which the tough library will trust instead of rejecting, ultimately compromising the integrity of software updates.

## Attack Chain

1.  Attacker gains delegated signing authority within a TUF repository.
2.  Attacker modifies delegated targets metadata to point to malicious software or manipulated metadata files. This could involve changing file hashes, lengths, or expiration dates to values that would normally be rejected.
3.  Attacker hosts the modified delegated targets metadata on their controlled server.
4.  A client using a vulnerable version of `tough` attempts to update its software using the TUF repository.
5.  The client downloads the attacker's modified delegated targets metadata.
6.  The vulnerable `load_delegations` function in `tough` fails to properly validate the expiration, hash, and length of the delegated targets metadata.
7.  The client trusts the malicious delegated targets metadata and proceeds to download the associated malicious software or metadata.
8.  The client's local metadata cache is poisoned, and subsequent updates may be compromised even if the attacker loses control of the delegated signing authority.

## Impact

Successful exploitation of this vulnerability allows an attacker to serve malicious software updates to clients using the `tough` library. This could lead to arbitrary code execution, data theft, or other malicious activities on the client's system. The number of affected clients depends on the adoption of the `tough` library and its use in software update mechanisms. This vulnerability primarily impacts software supply chain security, potentially affecting any sector relying on TUF for secure updates.

## Recommendation

*   Upgrade the `tough` library to version 0.22.0 or later to patch CVE-2026-6967.
*   Upgrade `tuftool` to version 0.15.0 or later to patch CVE-2026-6967.
*   Monitor network traffic for unexpected connections to untrusted or unknown hosts during software update processes. Analyze associated process executions.
*   Implement integrity checks on downloaded software packages beyond TUF metadata validation to provide defense in depth.
*   Examine application logs for errors related to metadata validation failures or unexpected software installations.
