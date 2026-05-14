---
title: Portainer Arbitrary File Read via Git Symlink Injection
slug: 2026-05-portainer-git-symlink-read
description: Portainer is vulnerable to an arbitrary file read vulnerability due to Git symlink injection when deploying stacks from Git repositories, allowing authenticated users to read sensitive files accessible to the Portainer process.
date: "2026-05-14T16:30:14Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - git
  - symlink
  - file-read
  - portainer
  - cve-2026-44881
  - vulnerability
vendors:
  - Portainer
products:
  - Portainer CE
  - Portainer
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
references:
  - https://github.com/advisories/GHSA-rpgq-m5fp-32wr
  - CVE-2026-44881
rules:
  - title: Detect Portainer Stack File Access to Sensitive Paths
    description: Detects attempts to read sensitive files via the Portainer stack file endpoint by checking for requests to access known sensitive file paths. Exploits CVE-2026-44881.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - discovery
    techniques:
      - T1068
      - T1190
    data_sources:
      - webserver
  - title: Detect Portainer Git Stack Creation from Suspicious Repositories
    description: Detects the creation of Git-backed stacks in Portainer that point to suspicious or untrusted Git repositories, which could indicate an attempt to exploit CVE-2026-44881 through symlink injection.
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1190
      - T1608.001
    data_sources:
      - webserver
rules_count: 2
---

Portainer is susceptible to an arbitrary file read vulnerability (CVE-2026-44881) stemming from Git symlink injection during stack deployment from Git repositories. An attacker with the ability to create or update Git-backed stacks can exploit this flaw. The vulnerability arises because Portainer uses `go-git` v5 to clone Git repositories, which translates Git symlink entries into OS symlinks without proper validation, except for `.gitmodules`. By crafting a repository containing a `docker-compose.yml` file that is a symbolic link to a sensitive file (e.g., `/etc/passwd`, Kubernetes service account token), an attacker can trick Portainer into reading and disclosing the contents of the linked file via the `GET /api/stacks/{id}/file` endpoint. Git-stack auto-update amplifies the issue by allowing deferred exploitation through a malicious commit that replaces `docker-compose.yml` with a symlink. This vulnerability affects Portainer releases from the introduction of Git-based stack deployment until the fixes in versions 2.33.8, 2.39.2, and 2.41.0.

## Attack Chain

1. An attacker creates a Git repository with a `docker-compose.yml` file configured as a symbolic link to a sensitive file (e.g., `/etc/passwd`).
2. The attacker uses the Portainer API or web interface to create a new stack, specifying the attacker-controlled Git repository as the source.
3. Portainer clones the Git repository using `go-git`, which creates the symlink on the filesystem.
4. An authenticated user (admin or non-admin, depending on configuration) triggers the file read by accessing the stack through Portainer's `GET /api/stacks/{id}/file` endpoint.
5. Portainer reads the `docker-compose.yml` file, which resolves to the attacker-specified target file due to the presence of the symlink.
6. The contents of the sensitive file are returned in the HTTP response to the user who initiated the request.
7. If auto-update is enabled, an attacker can push a malicious commit to an existing legitimate repository to replace the `docker-compose.yml` file with a symbolic link.
8. The file read is then triggered on the next scheduled update cycle with no further interaction required, leaking sensitive data without further user action.

## Impact

Successful exploitation of this vulnerability allows an attacker to read arbitrary files accessible to the Portainer process, typically running as root in containerized deployments. This includes sensitive files such as `/etc/shadow`, `/root/.ssh/*`, `/proc/self/environ`, and the Portainer BoltDB (`portainer.db`) containing user password hashes, API tokens, and agent credentials. In Kubernetes environments, the attacker can read the cluster service account token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/token`, granting the attacker the Portainer pod's cluster API access. Similarly, Docker Swarm secrets mounted into the Portainer container at `/run/secrets/` can be exposed. These leaked credentials can lead to onward compromise of managed Docker/Kubernetes environments, container registries, and Portainer itself.

## Recommendation

*   Upgrade to Portainer version 2.33.8, 2.39.2, or 2.41.0, where the vulnerability is fixed.
*   Disable **Allow non-admin users to manage their stacks** in environment settings to restrict stack creation to administrators, reducing the attack surface.
*   Carefully review and avoid deploying Git-backed stacks from untrusted repositories.
*   Disable auto-update on existing stacks to prevent deferred exploitation.
*   Deploy the Sigma rule `Detect Portainer Stack File Access to Sensitive Paths` to identify requests accessing sensitive files through the stack file endpoint.
*   Audit existing stack working directories for unexpected symlink entries under `/data/compose/` (or your configured data directory) using `find /data/compose -type l`.
*   Patch CVE-2026-44881 across all Portainer instances.
