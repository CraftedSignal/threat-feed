---
title: Path Traversal Vulnerability in Docker Compose OCI Artifact Processing
slug: 2026-08-docker-compose-path-traversal
description: CVE-2025-62725 is a critical path traversal vulnerability in Docker Compose, allowing for unauthorized file system access or manipulation during the processing of malicious OCI artifact layer annotations.
date: "2026-08-08T09:31:54Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - Docker
products:
  - Docker Compose
cves:
  - id: CVE-2025-62725
    epss: 0.13653
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-62725
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Update Docker Compose to the latest version to address CVE-2025-62725
      owner: IT Operations
      due: 48h
      evidence: CVE-2025-62725 update guidance
  mitigation_plan:
    - priority: immediate
      action: Restrict container registry access to known trusted sources
      owner: IT Operations
      addresses: CVE-2025-62725
      evidence: Path traversal via untrusted OCI artifacts
---

Microsoft has disclosed CVE-2025-62725, a security vulnerability affecting Docker Compose. The flaw resides in how the tool processes OCI artifact layer annotations. An attacker capable of crafting a malicious OCI artifact can leverage this path traversal vulnerability to access or manipulate files on the host system where Docker Compose is executed. This vulnerability poses a significant risk to development and build environments that ingest OCI artifacts from untrusted or compromised sources. Defenders should prioritize patching Docker Compose versions to the remediated release provided by the vendor, as this allows arbitrary file write or read access depending on the specific implementation context of the build process.

## Impact

Successful exploitation allows unauthorized file system access on the host, potentially leading to arbitrary code execution if an attacker can overwrite configuration files or binary paths used by the system. This impacts any environment utilizing Docker Compose for container orchestration or CI/CD pipelines, increasing the risk of supply chain compromise or container breakout.

## Recommendation

- Update Docker Compose to the latest version immediately to patch CVE-2025-62725.
- Audit CI/CD pipelines to ensure OCI artifacts are pulled only from trusted and verified registries.
- Monitor logs for unusual file system access patterns originating from the Docker Compose process.
