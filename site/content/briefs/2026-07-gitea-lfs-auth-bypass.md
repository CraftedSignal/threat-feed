---
title: Gitea LFS Authentication Bypass via Malformed SSH Sub-Verb
slug: 2026-07-gitea-lfs-auth-bypass
description: A high-severity authentication bypass vulnerability (CVE-2026-58423) in Gitea's SSH Git LFS handling allows any authenticated SSH user to obtain valid LFS credentials for any private repository, enabling unauthorized download of all LFS objects from instances running Gitea versions 1.23.0 through 1.26.2.
date: "2026-07-21T20:44:27Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - gitea
  - lfs
  - ssh
  - authentication-bypass
  - information-disclosure
  - vulnerability
vendors:
  - Gitea
products:
  - Gitea (1.23.0 to 1.26.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A flaw in SSH LFS sub-verb handling allows any authenticated SSH user to obtain valid LFS credentials.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This enables unauthorized download of all LFS objects from any private repository.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: This enables unauthorized download of all LFS objects from any private repository.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
    evidence: 'curl -X POST ... -H ''Authorization: Bearer eyJ...'' -d ''{"operation":"download"...}'''
    confidence_band: high
cves:
  - id: CVE-2026-58423
    cvss: 7.7
    epss: 0.0031
references:
  - https://github.com/advisories/GHSA-7wvc-rvp7-w99x
rules:
  - title: Detect CVE-2026-58423 Exploitation - Gitea LFS Auth Bypass Attempt
    description: Detects attempts to exploit CVE-2026-58423 in Gitea by using a malformed SSH LFS sub-verb to bypass authentication and obtain LFS credentials for private repositories. This rule identifies `git-lfs-authenticate` commands with non-standard sub-verbs.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1068
      - T1078.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

A critical flaw identified as CVE-2026-58423 exists within Gitea's handling of Git Large File Storage (LFS) over SSH. This vulnerability affects Gitea versions from 1.23.0 up to, but not including, 1.26.3, when deployed in production mode with SSH and LFS enabled. Any authenticated SSH user, regardless of their repository access permissions, can craft a malformed `git-lfs-authenticate` SSH command with an unrecognized sub-verb (e.g., "badverb"). This crafted command bypasses Gitea's standard permission checks, leading to the generation of valid LFS JWT tokens. Attackers can then leverage these tokens to download LFS objects from any private repository on the instance, leading to a significant confidentiality breach. The issue stems from insufficient validation of LFS sub-verbs in `cmd/serv.go` and `routers/private/serv.go`, combined with lax token validation for download operations in `services/lfs/server.go`.

## Attack Chain

1. An authenticated attacker, possessing a valid SSH key and access to a Gitea instance, targets a private repository for which they have no legitimate read permissions.
2. The attacker executes a crafted SSH command against the Gitea instance, using a malformed `git-lfs-authenticate` command with an invalid sub-verb (e.g., `ssh git@gitea-instance "git-lfs-authenticate admin/private-repo.git badverb"`).
3. Gitea's `getAccessMode` function, when encountering the unrecognized LFS sub-verb in a production environment, defaults to returning `perm.AccessModeNone` (value `0`) due to a logging-only error handling.
4. The subsequent permission check within `ServCommand` (at line ~322) evaluates `userMode < mode` as `userMode < 0`, which is always false, effectively bypassing the authorization check for private repositories.
5. Gitea proceeds to generate and return a valid LFS JWT token to the attacker, containing an `Op: "badverb"` claim.
6. The attacker uses the obtained JWT token to send an HTTP POST request to the Gitea LFS batch endpoint (e.g., `https://gitea-instance/admin/private-repo.git/info/lfs/objects/batch`), requesting download details for specific LFS objects.
7. The Gitea LFS server processes the request; importantly, it does not validate the `Op` field in the JWT token for download operations, thus accepting the illicit token.
8. The attacker then uses the provided download URLs and the stolen JWT token to `curl` and retrieve the private LFS object content, achieving unauthorized data exfiltration.

## Impact

This vulnerability constitutes a severe confidentiality breach, enabling any user with authenticated SSH access to a Gitea instance to gain unauthorized read access to Git LFS objects stored in *any* private repository on that instance. This includes scenarios where self-registration is enabled, allowing a malicious actor to register, obtain SSH access, and then compromise the confidentiality of all LFS data. The impact is significant for Gitea deployments relying on private repositories for sensitive code or data, as all LFS content within these repositories becomes vulnerable to unauthorized disclosure.

## Recommendation

* Patch CVE-2026-58423 immediately by updating Gitea instances to version `1.26.3` or newer.
* Deploy the Sigma rule "Detect CVE-2026-58423 Exploitation - Gitea LFS Auth Bypass Attempt" provided in this brief to your SIEM.
* Enable comprehensive `process_creation` logging on Gitea servers to monitor SSH command executions for unusual `git-lfs-authenticate` sub-verbs for detection of exploitation attempts.
