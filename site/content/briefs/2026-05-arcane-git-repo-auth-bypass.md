---
title: Arcane Git Repository Authentication Bypass Leads to Credential Exfiltration and GitOps Tampering (CVE-2026-45625)
slug: 2026-05-arcane-git-repo-auth-bypass
description: Arcane's REST API lacks proper admin authorization checks on Git repository management endpoints, allowing any authenticated user to exfiltrate stored Git credentials and tamper with GitOps configurations by redirecting credential requests to an attacker-controlled host.
date: "2026-05-18T13:45:14Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - credential-access
  - privilege-escalation
  - supply-chain-compromise
  - denial-of-service
  - information-disclosure
  - cloud
  - authentication-bypass
vendors:
  - GitHub
  - GitLab
products:
  - arcane backend (<= 1.18.1)
  - github.com
  - gitlab.com
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0042
    tactic_name: Resource Development
    technique_id: T1588
    technique_name: Obtain Capabilities
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://github.com/advisories/GHSA-7h26-hg47-p9hx
  - CVE-2026-45625
iocs:
  - type: domain
    value: attacker.tld
ioc_counts:
  domain: 1
rules:
  - title: Detect Arcane Git Repository URL Manipulation (CVE-2026-45625)
    description: Detects CVE-2026-45625 exploitation — modification of Git repository URLs to external domains via the Arcane API, indicating potential credential exfiltration or supply chain attacks.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - supply_chain_compromise
    techniques:
      - T1199
    data_sources:
      - webserver
  - title: Detect Arcane Git Repository Test Connection to External Domain (CVE-2026-45625)
    description: Detects CVE-2026-45625 exploitation — attempts to test the connection to a Git repository hosted on an external domain after a URL change.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - credential_access
    techniques:
      - T1071.001
    data_sources:
      - webserver
rules_count: 2
---

Arcane's huma-based REST API exposes nine endpoints under `/api/customize/git-repositories` and `/api/git-repositories/sync` for managing GitOps source repositories and their stored credentials. Eight of those endpoints never call the `checkAdmin(ctx)` helper used by other admin-managed resources, and the authentication middleware enforces only authentication, not the `admin` role. As a result, any logged-in user with the default `user` role can list, create, modify, delete, and test git repository configurations. By repointing an existing repository's URL to an attacker-controlled host while omitting the `token`/`sshKey` fields, the attacker causes Arcane to decrypt the legitimate PAT/SSH key on its next `/test`, `/branches`, or `/files` call and present it as HTTP Basic auth (or SSH key auth) to the attacker's host, exfiltrating plaintext Git credentials. This affects Arcane versions 1.18.1 and earlier.

## Attack Chain

1.  The attacker authenticates to the Arcane backend using a normal `user` account, either through registration or a pre-existing account.
2.  The attacker sends a `GET` request to `/api/customize/git-repositories` to enumerate all configured Git repositories, obtaining their IDs, URLs, and authentication types.
3.  The attacker crafts a `PUT` request to `/api/customize/git-repositories/{id}` with a JSON payload containing the key `url` set to an attacker-controlled domain (e.g., `https://attacker.tld/repo.git`). The `token` or `sshKey` fields are intentionally omitted to preserve the existing encrypted credentials.
4.  The Arcane backend updates the repository configuration, changing the repository URL while retaining the encrypted credentials.
5.  The attacker sends a `POST` request to `/api/customize/git-repositories/{id}/test` to trigger a connection test, or alternatively triggers a `GET` request to `.../branches` or `.../files` to list branches or browse files.
6.  Arcane decrypts the stored token or SSH key and attempts to authenticate to the attacker-controlled URL using HTTP Basic authentication or SSH key authentication.
7.  The attacker's server receives the decrypted credentials, which are exposed in cleartext.
8.  Optionally, the attacker cleans up by sending another `PUT` request to restore the original URL or `DELETE` requests to all repos for DoS.

## Impact

The vulnerability leads to cleartext exfiltration of stored Git credentials (PATs and SSH keys) configured by administrators for GitOps repositories. Stolen credentials grant write access to source repos, CI secrets, container registries, and production systems. Non-admin users can create, modify, and delete Git repository configurations, potentially injecting malicious code into deployments. An attacker can also trigger a denial of service by deleting repository configurations. Information disclosure of private repo contents is possible by listing files via the API. The default Arcane installations create new accounts with role `user`, making the attack easily exploitable. This has a critical impact on supply chain integrity and overall system security.

## Recommendation

*   Apply authorization checks on the `/api/customize/git-repositories` and `/api/git-repositories/sync` endpoints, ensuring that only admin users can manage Git repository configurations.
*   Implement stricter validation and sanitization of input data, particularly the repository URL, to prevent redirection to malicious hosts.
*   Deploy the Sigma rule "Detect Arcane Git Repository URL Manipulation" to identify attempts to modify Git repository URLs to attacker-controlled domains.
*   Deploy the Sigma rule "Detect Arcane Git Repository Test Connection to External Domain" to detect attempts to test connections to external domains after a URL manipulation.
*   Upgrade Arcane backend to a patched version beyond 1.18.1 that addresses CVE-2026-45625.
