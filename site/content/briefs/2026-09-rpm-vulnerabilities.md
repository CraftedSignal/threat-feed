---
title: Multiple Arbitrary Code Execution Vulnerabilities in RPM
slug: 2026-09-rpm-vulnerabilities
description: Multiple unpatched vulnerabilities in the RPM package manager allow an unauthenticated attacker to achieve arbitrary code execution on systems processing malicious packages.
date: "2026-09-25T14:01:04Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - linux
  - rpm
vendors:
  - RPM
products:
  - RPM
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker can exploit multiple vulnerabilities in RPM to execute arbitrary program code.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3567
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Review and restrict access to the 'rpm' binary for standard users via sudoers policy.
      owner: IT Operations
      due: 24h
      evidence: Arbitrary code execution via RPM handling.
  hunt_leads:
    - lead: Audit command line arguments for the 'rpm' binary to identify execution of packages from untrusted paths or temporary directories.
      technique_id: T1059
      data_needed:
        - Process creation logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation occurs during the package installation process.
  mitigation_plan:
    - priority: immediate
      action: Enforce package signing verification (GPG) for all repositories.
      owner: IT Operations
      addresses: Unverified package installation
      evidence: Restricting ingestion to trusted sources mitigates arbitrary package execution.
  gaps:
    - Lack of specific CVE IDs hinders automated patch management tracking.
---

The German Federal Office for Information Security (BSI) has released an advisory regarding multiple vulnerabilities within the RPM (RPM Package Manager) utility. These flaws are currently unpatched and present a significant risk to Linux distributions relying on RPM for software management. The vulnerabilities are triggered during the handling and installation of specially crafted RPM packages. An attacker capable of delivering a malicious package to a system administrator or automated package management process could exploit these flaws to execute arbitrary code with the privileges of the user or process performing the installation. Given the widespread use of RPM across enterprise Linux environments, this impact is considered critical for systems that frequently ingest third-party or untrusted software repositories.

## Impact

Successful exploitation allows for complete system compromise, including the installation of persistent backdoors, data exfiltration, or the deployment of ransomware. The scope of impact extends to all Linux distributions utilizing RPM, affecting server, desktop, and containerized environments.

## Recommendation

Prioritized actions for security teams:
* Monitor system logs for unexpected executions of the 'rpm' or 'dnf' binaries, particularly those occurring in automated build pipelines or unusual user contexts.
* Implement strict repository validation policies to ensure only signed packages from trusted sources are ingested.
* Audit build and deployment pipelines to identify automated processes that automatically pull and install RPM packages from external, non-verified sources.
* Restrict local installation of RPM packages to authorized administrators only.
* Monitor vendor-specific security mailing lists and repository mirrors for the release of security patches addressing these specific RPM vulnerabilities.
