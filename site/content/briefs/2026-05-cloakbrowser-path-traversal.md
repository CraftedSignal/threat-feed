---
title: CloakBrowser cloakserve Unauthenticated Path Traversal Leading to Arbitrary Directory Deletion (CVE-2026-45727)
slug: 2026-05-cloakbrowser-path-traversal
description: An unauthenticated path traversal vulnerability exists in CloakBrowser's cloakserve component (versions 0.3.27 and earlier) where a crafted fingerprint query parameter with path traversal sequences can be used to delete arbitrary directories accessible to the service user (CVE-2026-45727).
date: "2026-05-18T17:50:51Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - directory-deletion
  - cloakbrowser
  - CVE-2026-45727
vendors:
  - pip
products:
  - cloakbrowser (<= 0.3.27)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
references:
  - https://github.com/advisories/GHSA-mf33-gv72-w2h5
rules:
  - title: Detect CloakBrowser Path Traversal Attempt via Crafted Fingerprint
    description: Detects CVE-2026-45727 exploitation attempt — Monitors HTTP requests to the `cloakserve` endpoint with a crafted `fingerprint` parameter containing path traversal sequences.
    platform: sigma
    severity: high
    tactics:
      - impact
    techniques:
      - T1485
    data_sources:
      - webserver
  - title: Detect CloakBrowser cloakserve Binding to All Interfaces
    description: Detects CloakBrowser cloakserve binding to all interfaces (0.0.0.0) which could expose it to unnecessary network traffic.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

CloakBrowser's `cloakserve` component is vulnerable to an unauthenticated path traversal attack. The vulnerability stems from the direct use of the user-supplied `fingerprint` query parameter as a filesystem path component when creating Chrome profile directories. An attacker, without needing authentication, can send a crafted `fingerprint` value containing path traversal sequences to manipulate the `user_data_dir` resolution to point outside the intended `data_dir`. This vulnerability affects CloakBrowser versions 0.3.27 and earlier. The default configuration of `cloakserve` binding to `0.0.0.0` exacerbates the issue by making it network-exposed. By exploiting this vulnerability, attackers can delete arbitrary directories accessible to the service user when Chrome fails to start or during process cleanup.

## Attack Chain

1.  The attacker sends an HTTP request to the exposed `cloakserve` port.
2.  The request includes a crafted `fingerprint` query parameter containing path traversal sequences (e.g., `../`).
3.  `cloakserve` uses the `fingerprint` parameter to construct a path for the Chrome profile directory (`user_data_dir`).
4.  The path traversal sequences in the `fingerprint` parameter cause `user_data_dir` to resolve outside the configured `data_dir`.
5.  Chrome attempts to start using the manipulated `user_data_dir`.
6.  Chrome fails to start, potentially due to issues with the traversed path or profile directory.
7.  During cleanup or when the process is terminated, `shutil.rmtree()` is called to delete the `user_data_dir`.
8.  Due to the path traversal, `shutil.rmtree()` deletes an arbitrary directory accessible to the service user.

## Impact

Successful exploitation allows an unauthenticated attacker with network access to the `cloakserve` port to delete arbitrary directories accessible to the service user. The number of affected installations is unknown. This vulnerability allows for denial of service or potentially more severe impacts depending on the contents and permissions of the deleted directories.

## Recommendation

*   Upgrade CloakBrowser to version 0.3.28 or later to remediate the vulnerability as advised in the overview.
*   Restrict network access to the `cloakserve` port (typically port 8080) as described in the mitigations section of the linked advisory.
*   Deploy the Sigma rule "Detect CloakBrowser Path Traversal Attempt via Crafted Fingerprint" to monitor for suspicious `fingerprint` parameters containing path traversal sequences.
