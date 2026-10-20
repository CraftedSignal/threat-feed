---
brief_id: brief-2026-03-29-trivy-supply-chain
event_id: brief-2026-03-29-trivy-supply-chain
revision: 2
activity_at: "2026-03-29T07:19:13Z"
revision_history:
  - revision: 2
    at: "2026-10-20T13:19:21Z"
    checksum: sha256:c8ab88c6f35fbd56879bf30865a4f1d541e151f0b1cc847a3aa2ea3e7cf86603
    summary: Repaired a legacy canonical identity collision
    changed_fields:
      - slug
    maintenance: true
title: Compromised trivy-action GitHub Action Enables Credential Theft
slug: 2026-03-29-trivy-supply-chain
description: The aquasecurity/trivy-action GitHub Action was compromised via git tag repointing, replacing the legitimate entry point with a multi-stage credential stealer, enabling access to secrets, credentials, and infrastructure in CI/CD pipelines.
date: "2026-03-29T07:19:13Z"
type: advisory
types:
  - advisory
severities:
  - critical
exploitation_evidence:
  status: unknown
tags:
  - supply-chain
  - github-actions
  - credential-theft
  - ci/cd
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
references:
  - https://www.crowdstrike.com/en-us/blog/from-scanner-to-stealer-inside-the-trivy-action-supply-chain-compromise/
rules:
  - title: Detect Suspicious Script Execution in GitHub Actions
    description: Detects suspicious shell scripts running within GitHub Actions runners that may indicate a compromised action.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.004
    data_sources:
      - process_creation
      - linux
  - title: Detect Runner Process Discovery
    description: Detects the enumeration of running processes within a GitHub Actions runner which is done to discover attack vectors.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1057
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On March 19, 2026, a spike in suspicious script execution on Linux GitHub Actions runners was observed. Investigation revealed that the aquasecurity/trivy-action GitHub Action, a popular open-source vulnerability scanner used in CI/CD pipelines, had been compromised. The attackers used git tag repointing to retroactively poison 76 of the scanner's 77 release tags, replacing the legitimate entry point with a multi-stage credential stealer. This malicious code ran before the real scanner, allowing workflows to complete without raising suspicion. The compromised action had access to the runner's environment, secrets, credentials, and network. Aqua Security confirmed the compromise of the Trivy GitHub Action script, setup script, and binary and removed the malicious artifacts.

## Attack Chain

1.  **Initial Access:** The attacker compromised the aquasecurity/trivy-action GitHub Action by repointing git tags.
2.  **Delivery:** Developers unknowingly included the compromised action in their CI/CD workflows by referencing the poisoned tags (e.g., `@0.24.0`).
3.  **Execution:** When a workflow ran, the GitHub Actions runner downloaded and executed the malicious `entrypoint.sh` script.
4.  **Discovery:** The malicious `entrypoint.sh` enumerated process IDs (PIDs) running on the runner.
5.  **Credential Access:** The script then attempted to steal credentials from the runner environment.
6.  **Concealment:** The script executed the legitimate Trivy scanner logic after the malicious code, masking the compromise.
7.  **Exfiltration (Likely):** Although not explicitly stated, the stolen credentials would likely be exfiltrated to an attacker-controlled server.
8.  **Impact:** Unauthorized access to cloud resources, code repositories, and internal infrastructure using stolen credentials.

## Impact

The compromise of the trivy-action GitHub Action potentially affected a large number of organizations using the scanner in their CI/CD pipelines. Successful exploitation could lead to the theft of sensitive credentials, unauthorized access to cloud resources, code repositories, and internal infrastructure, resulting in data breaches, supply chain attacks, and significant financial losses. The number of victims is unknown but could be substantial given the widespread adoption of the compromised action.

## Recommendation

*   Review CI/CD pipelines for usage of `aquasecurity/trivy-action` and verify the integrity of referenced tags/versions.
*   Monitor process execution on GitHub Actions runners for suspicious script activity as outlined in the Attack Chain. Enable process creation logging on runners.
*   Deploy the Sigma rule "Detect Suspicious Script Execution in GitHub Actions" to identify potential exploitation attempts.
*   Implement stricter controls and auditing around GitHub Action permissions and secret management.
*   Consider using checksum verification or other integrity checks to ensure the authenticity of GitHub Actions.
