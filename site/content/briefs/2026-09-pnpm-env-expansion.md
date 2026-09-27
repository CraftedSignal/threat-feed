---
title: Arbitrary Environment Variable Disclosure via pnpm-workspace.yaml
slug: 2026-09-pnpm-env-expansion
description: Vulnerable pnpm versions expand sensitive environment variables within proxy settings in malicious pnpm-workspace.yaml files, enabling credential exfiltration during configuration loading.
date: "2026-09-27T19:08:52Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:pnpm:pnpm:*:*:*:*:*:*:*:*
tags:
  - supply-chain
  - pnpm
  - vulnerability
  - credential-theft
vendors:
  - pnpm
products:
  - pnpm (11.0.0 <= version < 11.11.0)
  - pnpm (10.7.0 <= version < 10.34.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1566
    technique_name: Phishing
    evidence: An attacker who controls a repository's pnpm-workspace.yaml can cause a victim who clones the repository and runs a pnpm command to expand environment secrets.
    confidence_band: med
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1204
    technique_name: User Execution
    evidence: A victim who clones the repository and runs a pnpm command (e.g. pnpm install) to expand environment secrets.
    confidence_band: high
cves:
  - id: CVE-2026-101043
    cvss: 7.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101043
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Development Security
  immediate_actions:
    - action: Upgrade pnpm to 11.11.0 or 10.34.5
      owner: IT Operations
      due: 48h
      evidence: Fixed in pnpm 11.11.0 and 10.34.5.
  mitigation_plan:
    - priority: immediate
      action: Rotate NPM_TOKEN and GITHUB_TOKEN credentials
      owner: Development Security
      addresses: CVE-2026-101043
      evidence: Exfiltration of environment secrets such as NPM_TOKEN or GITHUB_TOKEN.
---

CVE-2026-101043 affects pnpm versions 11.0.0 through 11.10.x and 10.7.0 through 10.34.4. The vulnerability arises from improper handling of environment variable expansion within the httpProxy, httpsProxy, and noProxy configuration keys located in a project's pnpm-workspace.yaml file. Unlike other sensitive keys that are protected from expansion to prevent untrusted manifest exploitation, these proxy keys are processed before lifecycle scripts execute. 

An attacker can create a malicious pnpm-workspace.yaml file within a repository that references sensitive environment variables such as NPM_TOKEN or GITHUB_TOKEN. When a victim clones the repository and executes a pnpm command like pnpm install, the pnpm client expands these variables into the proxy configuration. This leads to the exfiltration of the token values via DNS queries or HTTP traffic routed through an attacker-controlled proxy server. This vulnerability allows for unauthorized access to private package registries and CI/CD environments.

## Attack Chain

1. Attacker creates a malicious repository containing a crafted pnpm-workspace.yaml file.
2. Attacker sets the httpProxy or httpsProxy key in the manifest to include an environment variable placeholder (e.g., ${NPM_TOKEN}).
3. Attacker lures a victim to clone the repository into their local environment.
4. Victim executes a standard pnpm command (e.g., pnpm install) within the root of the cloned repository.
5. pnpm loads the pnpm-workspace.yaml manifest and parses the proxy configuration.
6. The client engine expands the placeholder ${NPM_TOKEN} into its actual sensitive value.
7. The pnpm process triggers a network connection or DNS lookup toward an attacker-controlled proxy host, appending the expanded token to the request metadata.
8. Attacker logs the incoming connection or DNS request on their infrastructure to capture the exfiltrated secret.

## Impact

Successful exploitation leads to the theft of sensitive development credentials, including NPM_TOKEN and GITHUB_TOKEN. This allows attackers to authenticate as the victim, potentially accessing private repositories, stealing proprietary source code, or injecting malicious packages into the software supply chain.

## Recommendation

- Upgrade pnpm to version 11.11.0 or 10.34.5 immediately to include the fix that prevents environment variable expansion in untrusted proxy configurations.
- Implement repository scanning tools to detect pnpm-workspace.yaml files containing suspicious proxy configurations or references to environment variable patterns.
- Rotate all credentials that may have been stored in local environment variables (e.g., NPM_TOKEN, GITHUB_TOKEN) if they were used in environments where malicious repositories were cloned and processed.
