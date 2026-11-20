---
brief_id: brief-2026-11-20-git-lfs-rce-ghsa-x72p-hmqp-46hw
event_id: brief-2026-11-20-git-lfs-rce-ghsa-x72p-hmqp-46hw
revision: 1
activity_at: "2026-11-20T20:09:08Z"
title: 'Git LFS: Arbitrary command execution via crafted configurations (CVE-2026-105803)'
slug: 2026-11-git-lfs-rce-ghsa-x72p-hmqp-46hw
description: Git LFS is vulnerable to arbitrary command execution when fetching objects from a malicious repository due to insufficient filtering of configuration options in the .lfsconfig file, affecting versions 1.3.0 through 2.13.3 and 3.0.0 through 3.8.0.
date: "2026-11-20T20:09:08Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:git_lfs:git_lfs:*:*:*:*:*:*:*:*
vendors:
  - git-lfs
products:
  - git-lfs
cves:
  - id: CVE-2026-105803
    epss: 0.00545
    kev_status: "false"
references:
  - https://cveawg.mitre.org/api/cve/CVE-2026-105803
  - https://github.com/advisories/GHSA-x72p-hmqp-46hw
---

## Overview
Git LFS (Large File Storage) is a Git extension for versioning large files. A vulnerability exists where Git LFS fails to correctly filter the limited set of options permitted in a repository's .lfsconfig file when option keys contain certain additional components. This allows an attacker to craft keys that mimic options used to configure custom object transfer commands.

## Attack Chain
When a user fetches objects from a malicious repository, Git LFS may interpret crafted .lfsconfig keys to use an attacker-selected command or binary, resulting in execution during the transfer process.

## Impact
Successful exploitation allows the execution of an arbitrary command or binary on the system of any user who performs a fetch operation on a malicious repository.

## Recommendation
Upgrade to Git LFS version 3.8.1. The vulnerability is resolved by restricting the configuration of custom object transfer commands to local Git configuration files. As a workaround, users and administrators should avoid cloning repositories from untrusted sources, or disable Git LFS entirely.
