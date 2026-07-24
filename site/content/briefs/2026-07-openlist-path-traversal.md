---
title: OpenList Path Traversal Vulnerability Allows Renaming Files Outside Authorized Paths
slug: 2026-07-openlist-path-traversal
description: An authenticated user with rename permissions in OpenList/v4 is vulnerable to a path traversal flaw (GHSA-95cv-r8x4-vh75) in the `/api/fs/batch_rename` handler, allowing them to rename files outside their authorized base path and source directory by injecting traversal segments in the `src_name` parameter, leading to integrity violations and limited availability impact.
date: "2026-07-24T22:34:55Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - path-traversal
  - authenticated-bypass
  - integrity-violation
  - web-application
vendors:
  - OpenListTeam
products:
  - OpenList/v4 <= 4.2.3
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: An authenticated user with rename permission can set `src_name` to traversal segments such as `../../ab/secret.txt`.
    confidence_band: high
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1083
    technique_name: File and Directory Discovery
    evidence: it may reveal whether guessed out-of-base files exist based on success or error responses.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: It can also cause limited availability impact by moving files away from expected names
    confidence_band: med
references:
  - https://github.com/advisories/GHSA-95cv-r8x4-vh75
---

A high-severity path traversal vulnerability (GHSA-95cv-r8x4-vh75) has been identified in OpenList/v4, specifically affecting versions up to and including 4.2.3. The flaw resides within the `/api/fs/batch_rename` handler, which is responsible for batch file renaming operations. The vulnerability stems from insufficient validation of the `src_name` parameter in the HTTP POST request body. While the `new_name` parameter is properly checked for path separators, `src_name` is not, allowing an authenticated user with rename permissions to supply directory traversal segments (e.g., `../../`) within `src_name`. This enables the attacker to manipulate the final source path to rename files located outside their designated base path and authorized `src_dir`, bypassing intended access controls and affecting other users' data.

## Attack Chain

1. An authenticated user with file `rename` permissions crafts an HTTP POST request targeting the `/api/fs/batch_rename` endpoint.
2. The request's JSON body specifies a `src_dir` (e.g., `/writable`) that is within the user's legitimately authorized base path (e.g., `/team/a`).
3. Within the `rename_objects` array in the JSON payload, the user sets the `src_name` parameter to include directory traversal segments (e.g., `../../ab/secret.txt`).
4. The `FsBatchRename` handler processes the request but fails to adequately validate the `src_name` parameter for path traversal sequences.
5. OpenList concatenates the provided `src_dir` and the attacker-controlled `src_name` to construct a full source path (e.g., `/team/a/writable/../../ab/secret.txt`).
6. Lower-level filesystem path normalization functions resolve these traversal segments, resulting in a final, absolute source path (e.g., `/team/ab/secret.txt`) that unexpectedly escapes the user's authorized directory.
7. The application proceeds to rename the file located at this normalized, out-of-scope path (`/team/ab/secret.txt`) to the specified `new_name` (e.g., `renamed.txt`), thereby performing an unauthorized file modification.

## Impact

This vulnerability allows an authenticated user to violate the integrity of other users' files by renaming them outside their authorized scope. In a multi-user OpenList deployment, a user confined to a specific base path (e.g., `/team/a`) can rename sibling files (e.g., `/team/ab/secret.txt`) belonging to other users. This can lead to limited availability, as crucial files may be moved from their expected locations, disrupting operations. Furthermore, by observing success or error responses from such rename attempts, an attacker could potentially confirm the existence of guessed files outside their base path, aiding in reconnaissance.

## Recommendation

Prioritize applying the security patch for OpenList/v4 to address GHSA-95cv-r8x4-vh75 immediately. Implement robust validation for the `renameObject.SrcName` parameter within the `/api/fs/batch_rename` handler by applying the same `checkRelativePath` constraints currently used for `renameObject.NewName`. Alternatively, ensure that source objects are derived exclusively from a trusted directory listing of `reqPath`.
