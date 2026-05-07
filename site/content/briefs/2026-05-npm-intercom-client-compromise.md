---
title: Compromised intercom-client npm Package Exfiltrates Credentials
slug: 2026-05-npm-intercom-client-compromise
description: A compromised version (7.0.4) of the intercom-client npm package was published using a compromised developer account, containing obfuscated JavaScript that executed during installation to harvest and exfiltrate credentials from the environment, as part of the 'Mini Shai-Hulud' supply chain campaign.
date: "2026-05-08T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - npm
vendors:
  - npm
  - GitHub
  - Amazon
  - Google
  - Microsoft
  - Intercom
products:
  - intercom-client (= 7.0.4)
  - AWS
  - GCP
  - Azure
  - github.com
  - npm
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1608
    technique_name: Stage Capabilities
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1555
    technique_name: Credentials from Information Repositories
references:
  - https://github.com/advisories/GHSA-54pg-9963-v8vg
  - https://socket.dev/blog/intercom-s-npm-package-compromised-in-supply-chain-attack
  - https://www.intercomstatus.com/us-hosting/incidents/01KQFN6VS6ARP1XBR1K1SBYY59
  - https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm
rules:
  - title: Detect Suspicious npm Preinstall Script
    description: Detects execution of unusual commands from npm preinstall scripts, potentially indicating a supply chain attack.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1608.001
    data_sources:
      - process_creation
      - linux
  - title: Detect Credential Harvesting via Environment Variable Access
    description: Detects processes attempting to access a large number of environment variables, which is a common technique for credential harvesting.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1555
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

On April 30, 2026, version 7.0.4 of the intercom-client npm package was published using a compromised developer account. This version was not created through Intercom's official build pipeline. The malicious package contained an obfuscated JavaScript payload that was designed to execute upon installation via a `preinstall` hook. This payload was designed to harvest sensitive credentials from the environment in which it was running, including cloud provider credentials (AWS, GCP, and Azure), environment variables, `.env` files, GitHub and npm tokens, SSH keys, local configuration files, and cloud metadata service credentials. The stolen credentials were then exfiltrated to attacker-controlled GitHub repositories. The compromised package was available on npm for approximately 2 hours, between 15:00 and 17:00 UTC. This incident is part of the "Mini Shai-Hulud" supply chain campaign, as tracked by Wiz and Socket. Developers are advised to check their projects for the presence of version 7.0.4 using `npm list intercom-client` and rotate credentials if found.

## Attack Chain

1.  The attacker compromises a developer account with publishing privileges for the intercom-client npm package.
2.  The attacker publishes a malicious version of the intercom-client package (version 7.0.4) to npm.
3.  The malicious package includes an obfuscated JavaScript payload within a `preinstall` hook.
4.  When a developer installs the compromised package using `npm install intercom-client`, the `preinstall` script automatically executes.
5.  The obfuscated JavaScript payload harvests credentials from the environment, including cloud provider credentials (AWS, GCP, Azure), environment variables, .env files, GitHub and npm tokens, SSH keys, local configuration files, and cloud metadata service credentials.
6.  The harvested data is exfiltrated to attacker-controlled GitHub repositories.
7.  The attacker gains access to the stolen credentials, potentially allowing them to compromise cloud infrastructure, source code repositories, and other sensitive resources.

## Impact

The compromise of the intercom-client npm package resulted in the potential theft of sensitive credentials, including cloud provider credentials, API keys, and SSH keys. The impact could include unauthorized access to cloud infrastructure, source code repositories, and other sensitive resources. This attack affects any developer or organization that installed version 7.0.4 of the intercom-client package between 15:00 and 17:00 UTC on April 30, 2026. The long-term consequences depend on the extent to which the stolen credentials are used to further compromise systems and data.

## Recommendation

*   Downgrade the intercom-client package to version 7.0.3 or earlier to avoid the compromised version, as mentioned in the [Patches](#patches) section.
*   Immediately rotate all credentials (cloud provider credentials, environment variables, API keys, SSH keys) accessible from any environment where version 7.0.4 was installed, as recommended in the [Workarounds](#workarounds) section.
*   Review CI/CD build logs for any `npm install` commands that resolved to version 7.0.4 between 15:00 and 17:00 UTC on April 30, 2026, to identify potentially affected systems, as described in the [Workarounds](#workarounds) section.
*   Deploy the Sigma rule "Detect Suspicious npm Preinstall Script" to identify potentially malicious npm package installations based on unusual script execution.
