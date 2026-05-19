---
title: Malicious @beproduct/nestjs-auth Package Contains Mini Shai-Hulud Worm (CVE-2026-46412)
slug: 2026-05-mini-shai-hulud
description: Between May 11th and May 12th of 2026, a threat actor compromised an npm publish token to publish 18 malicious versions of the '@beproduct/nestjs-auth' package (versions 0.1.2 through 0.1.19) containing payloads from the Mini Shai-Hulud npm supply-chain worm campaign that exfiltrated npm tokens, GitHub PATs/OAuth tokens, AWS credentials, and Vault tokens, impacting developer environments.
date: "2026-05-19T20:29:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - npm
  - credential-theft
  - exfiltration
  - worm
vendors:
  - npmjs
  - GitHub
  - AWS
  - HashiCorp
  - BeProduct
products:
  - '@beproduct/nestjs-auth (>= 0.1.2, <= 0.1.19)'
  - github.com
  - actions
  - Vault
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1543
    technique_name: Create or Modify System Process
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1003
    technique_name: OS Credential Dumping
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1119
    technique_name: Automated Collection
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1041
    technique_name: Exfiltration Over C2 Channel
references:
  - https://github.com/advisories/GHSA-6xwp-cp5h-q856
  - https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
  - https://www.aikido.dev/blog/checklist-github-actions
iocs:
  - type: url
    value: https://filev2.getsession.org
  - type: ip
    value: 169.254.169.254
  - type: domain
    value: registry.npmjs.org
  - type: domain
    value: vault.svc.cluster.local
  - type: hash_sha256
    value: 2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96
  - type: hash_sha256
    value: ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c
ioc_counts:
  domain: 2
  hash_sha256: 2
  ip: 1
  url: 1
rules:
  - title: Detect Suspicious NPM Package Postinstall Script
    description: Detects the execution of suspicious postinstall scripts in npm packages based on common process names, file paths, and network connections associated with malicious activity.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
      - execution
    techniques:
      - T1059.001
      - T1204.002
    data_sources:
      - process_creation
      - windows
  - title: Detect Mini Shai-Hulud Exfiltration
    description: Detects connections to the Mini Shai-Hulud exfiltration domain filev2.getsession.org
    platform: sigma
    severity: medium
    tactics:
      - exfiltration
    techniques:
      - T1041
    data_sources:
      - network_connection
      - windows
rules_count: 2
---

Between 2026-05-11 20:19 UTC and 22:56 UTC, an attacker used a compromised npm publish token to publish 18 malicious versions of `@beproduct/nestjs-auth` (0.1.2 through 0.1.19). The packages contained payloads from the **Mini Shai-Hulud** npm supply-chain worm campaign. This campaign is also described by Aikido Security, indicating a resurgence of known tactics. npm Security removed the malicious versions from the registry shortly after publication, but any developer who ran `npm install @beproduct/nestjs-auth` resolving to a version in the affected range during that window executed the malicious postinstall script, potentially compromising their environment. Version `0.1.20` is a clean republish. This incident underscores the risks of supply chain attacks targeting developer tooling and the importance of securing npm publish tokens. CVE-2026-46412 is assigned to this vulnerability.

## Attack Chain

1.  Attacker compromises an npm publish token.
2.  Attacker publishes malicious versions (0.1.2 - 0.1.19) of the `@beproduct/nestjs-auth` package to the npm registry.
3.  A developer unknowingly installs a malicious version of the package via `npm install @beproduct/nestjs-auth`.
4.  The malicious package's postinstall script executes.
5.  The postinstall script attempts to harvest npm tokens (~/.npmrc), GitHub PATs/OAuth tokens, AWS credentials (env vars, ~/.aws/credentials), and HashiCorp Vault tokens, and other secrets from environment variables.
6.  The harvested secrets are exfiltrated to `https://filev2.getsession.org`.
7.  The script writes persistence artifacts (`tanstack_runner.js`, `router_init.js`, `setup.mjs`) and IDE hook configurations (`.claude/`, `.vscode/`) into the developer's working tree.
8. The worm attempts to commit `setup.mjs` and hook configurations to PR branches.

## Impact

This supply chain attack compromised developer environments by injecting malicious code via a popular npm package. Successful exploitation allowed the attacker to steal sensitive credentials, including npm tokens, GitHub PATs/OAuth tokens, AWS credentials, and HashiCorp Vault tokens. The exfiltration of these secrets could lead to further compromise of the victim's infrastructure, including source code repositories, cloud environments, and CI/CD pipelines. The persistence mechanisms ensure that the attacker maintains access even after the initial infection vector is removed. There is no reliable data about the precise number of victims, but any developer who installed the package within the 2 hour 37 minute window is potentially compromised.

## Recommendation

*   Deploy the "Detect Suspicious NPM Package Postinstall Script" Sigma rule to detect execution of malicious postinstall scripts based on process names, file paths and network connections.
*   Deploy the "Detect Mini Shai-Hulud Exfiltration" Sigma rule to detect connections to the exfiltration domain `filev2.getsession.org`.
*   Block the exfiltration domain `filev2.getsession.org` at the network perimeter using the IOC table.
*   Monitor for connections to cloud metadata endpoints (`169.254.169.254`) and vault probes (`vault.svc.cluster.local:8200`) from developer workstations, as these are unusual and may indicate compromised environments using the IOC table.
*   Scan systems for the presence of persistence artifacts such as `tanstack_runner.js`, `router_init.js`, and suspicious IDE configuration files in `.claude/` and `.vscode/` directories as listed in the IOC table.
*   Immediately rotate all potentially exposed credentials if any version in the range `>=0.1.2 <=0.1.19` of `@beproduct/nestjs-auth` was installed in your environment, as described in the mitigation steps.
