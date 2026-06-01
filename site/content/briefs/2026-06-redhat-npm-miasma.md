---
title: Red Hat npm Packages Compromised by Miasma Malware
slug: 2026-06-redhat-npm-miasma
description: A supply chain attack compromised over 30 npm packages under Red Hat's '@redhat-cloud-services' namespace, distributing a credential-stealing malware variant named 'Miasma' that targets sensitive developer information.
date: "2026-06-01T21:39:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain
  - credential-theft
  - miasma
  - npm
vendors:
  - Red Hat
products:
  - '@redhat-cloud-services npm packages'
  - GitHub Actions
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://www.bleepingcomputer.com/news/security/red-hat-npm-packages-compromised-to-steal-developer-credentials/
rules:
  - title: Detect npm Package Preinstall Script Execution
    description: Detects execution of scripts defined in the 'preinstall' property of an npm package, which is used by the Miasma malware.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect GitHub Actions Workflow Publishing to npm
    description: Detects GitHub Actions workflows publishing packages to npm, potentially indicating compromised workflows used in supply chain attacks.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
      - initial_access
    techniques:
      - T1071.001
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On June 1, 2026, Red Hat disclosed a supply chain attack targeting more than 30 npm packages within their '@redhat-cloud-services' namespace. The attack involved injecting a new variant of the Shai-Hulud credential-stealing malware, dubbed "Miasma," into compromised packages. This malware is designed to harvest sensitive information, including developer credentials, cloud secrets, SSH keys, CI/CD tokens, and other valuable data. Aikido and OX Security discovered the incident, noting that the affected packages receive approximately 117,000 weekly downloads. Red Hat has removed the malicious packages from the npm registry. The attacker allegedly compromised a Red Hat employee's GitHub account to push malicious commits. Miasma has been found in 309 GitHub repositories.

## Attack Chain

1.  The attacker compromises a Red Hat employee's GitHub account.
2.  Malicious commits are pushed to multiple repositories via the compromised GitHub account.
3.  A GitHub Actions workflow is added to the repositories.
4.  A script is introduced to abuse npm's publishing mechanism.
5.  The workflow installs Bun and executes `_index.js`, passing a list of target packages via the `OIDC_PACKAGES` environment variable.
6.  The script uses the `id-token: write` permission to request a short-lived OIDC token from GitHub.
7.  The OIDC token authenticates directly with npm's trusted publishing endpoint.
8.  Backdoored versions of the packages are published, containing a 'preinstall' script executing a heavily obfuscated `index.js` to steal secrets.

## Impact

This supply chain attack could lead to the theft of sensitive developer credentials, cloud secrets (AWS, Google Cloud, Azure), SSH keys, CI/CD tokens, HashiCorp Vault tokens, Kubernetes service account tokens, npm and PyPI publishing tokens, Docker credentials, GPG keys, and `.env` files. Over 30 npm packages and 96 versions under the `@redhat-cloud-services` namespace were affected, with approximately 117,000 weekly downloads. This could result in widespread compromise of internal development tools and potentially impact customer and partner environments if credentials used in those environments were compromised.

## Recommendation

*   Rotate all credentials, secrets, and tokens utilized by code on any infected device (as per the report's recommendations).
*   Deploy the Sigma rule for detection of npm package preinstall script execution to your SIEM and tune for your environment.
*   Monitor GitHub Actions workflows for suspicious activity, specifically the use of `id-token: write` permission, as described in the Attack Chain.
*   Implement multi-factor authentication (MFA) on all developer accounts, especially GitHub, to prevent account compromise (as indicated by the initial access vector).
