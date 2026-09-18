---
title: Potential Unauthorized Secret Scanning via Gitleaks
slug: 2026-09-gitleaks-misuse
description: Threat actors may leverage the legitimate open-source tool 'Gitleaks' to perform unauthorized secret scanning on compromised hosts to identify and exfiltrate sensitive credentials from source code repositories.
date: "2026-09-18T19:08:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - credential-access
  - collection
  - gitleaks
  - threat-detection
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: This rule detects the execution of Gitleaks, a tool used to search for high-entropy strings and secrets in code repositories, which may indicate an attempt to access credentials.
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1213
    technique_name: Data from Information Repositories
    evidence: An attacker may clone internal repos or traverse local workspace directories, drop a portable gitleaks binary, run recursive scans, then archive the results to exfiltrate tokens.
    confidence_band: high
rules:
  - title: Potential Secret Scanning via Gitleaks
    description: Detects the execution of the Gitleaks binary, which may indicate unauthorized credential harvesting from code repositories.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1213.003
      - T1552.001
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for Gitleaks binary execution in unauthorized directories.
      owner: Detection Engineering
      due: 24h
      evidence: Source detection rule guidance.
  hunt_leads:
    - lead: Search for files with extensions .json, .sarif, or .csv modified in directories where Gitleaks was executed.
      technique_id: T1552.001
      data_needed:
        - File creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Guidance on locating and inspecting newly created artifacts.
  mitigation_plan:
    - priority: short_term
      action: Enforce execution blocklists for known portable binaries in non-standard directories via EDR.
      owner: IT Operations
      addresses: Unauthorized tool usage
      evidence: Guidance on eradicating tooling.
---

Gitleaks is a legitimate open-source utility designed for security professionals and developers to detect high-entropy strings, API keys, and passwords within code repositories. However, threat actors have increasingly repurposed this tool to support post-compromise activities. By dropping a portable Gitleaks binary onto a compromised host, attackers can perform recursive scans against local workspaces or cloned internal repositories to harvest credentials. 

The scope of this threat involves the identification of secrets that are subsequently exfiltrated, enabling lateral movement and service impersonation. Defenders should monitor for Gitleaks execution from atypical, user-writable directories (e.g., /tmp, %TEMP%, or user profiles) and look for command-line arguments that direct output to files (JSON/SARIF) or staging locations for exfiltration. This behavior is often associated with unauthorized access to internal codebases and sensitive development environments.

## Impact

Successful exploitation allows attackers to gain unauthorized access to cloud API keys, SSH keys, service tokens, and developer credentials. The potential damage includes widespread service impersonation, unauthorized access to downstream systems, and the exfiltration of proprietary source code. If deployed across a large CI/CD environment or a developer's workstation, the impact can extend to entire production infrastructures.

## Recommendation

- Implement monitoring for the execution of 'gitleaks' or 'gitleaks.exe' using the provided detection rules to identify potentially unauthorized scans.
- Establish an allowlist or application control policy to restrict the execution of binaries in user-writable directories like %TEMP% and /tmp.
- Conduct proactive hunting for 'gitleaks.json', '.sarif', or '.csv' files generated in unexpected directories, as these often serve as staging files for exfiltrated credentials.
- Enforce legitimate secret scanning via approved CI/CD pipelines to reduce the necessity for, and therefore the visibility of, ad-hoc manual scans.
- Immediately rotate any credentials identified in exfiltrated reports and review git history for committed secrets.
