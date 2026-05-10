---
title: Compromised intercom-php Package on GitHub
slug: 2026-05-intercom-php-supply-chain
description: A malicious commit tagged as version 5.0.2 was pushed to the intercom/intercom-php repository on GitHub, containing a Composer plugin that downloaded the Bun JavaScript runtime and executed an obfuscated credential-harvesting payload, targeting cloud provider credentials, environment variables, SSH keys, and CI/CD secrets.
date: "2026-05-08T12:00:00Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - Mini Shai-Hulud
tags:
  - supply-chain
  - credential-theft
  - github
vendors:
  - Intercom
products:
  - intercom-php
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://github.com/advisories/GHSA-gr3r-crp5-qrrm
  - https://www.intercomstatus.com/us-hosting/incidents/01KQFN6VS6ARP1XBR1K1SBYY59
  - https://www.wiz.io/blog/mini-shai-hulud-supply-chain-sap-npm
rules:
  - title: Detect Bun Execution
    description: Detects the execution of the Bun JavaScript runtime, which was used as part of the intercom-php supply chain attack to execute a credential-harvesting payload.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1566.001
    data_sources:
      - process_creation
      - windows
  - title: Detect Composer Plugin Installation
    description: Detects the installation of Composer plugins which could indicate the presence of a malicious plugin from a compromised package.
    platform: sigma
    severity: low
    tactics:
      - installation
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

On April 30, 2026, the intercom/intercom-php repository on GitHub was subject to a supply chain attack. A compromised service account, `github-management-service`, was used to push a malicious commit tagged as version 5.0.2. This attack is part of the broader "Mini Shai-Hulud" campaign, which also targeted the `intercom-client` package on npm. The malicious version of `intercom-php` included a Composer plugin designed to act as a dropper. It downloaded the Bun JavaScript runtime (version 1.3.13) and executed an obfuscated credential-harvesting payload. The malicious tag was live for approximately 1 hour and 44 minutes, between 20:53 UTC and 22:37 UTC on April 30, 2026, before being identified and reverted. This incident highlights the risk of supply chain attacks targeting widely-used packages and the potential for significant credential compromise.

## Attack Chain

1. A compromised service account (`github-management-service`) pushes a malicious commit to the `intercom/intercom-php` repository.
2. The malicious commit is tagged as version 5.0.2 and published to GitHub.
3. Developers using `intercom-php` may inadvertently install the malicious version via `composer update` or `composer install` if performed during the compromised window.
4. The Composer plugin within the malicious package is executed during the installation process.
5. The plugin downloads the Bun JavaScript runtime (version 1.3.13) to the affected system.
6. The Bun runtime executes an obfuscated JavaScript payload.
7. The JavaScript payload attempts to harvest credentials, including cloud provider credentials (AWS, GCP, Azure), environment variables, .env files, SSH keys, local configuration files, and CI/CD secrets.
8. The harvested credentials could then be exfiltrated by the attacker for unauthorized access to cloud resources and sensitive data.

## Impact

This supply chain attack directly compromised the `intercom-php` package, potentially affecting any project that installed or updated to version 5.0.2 between 20:53 UTC and 22:37 UTC on April 30, 2026. Successful exploitation leads to the theft of sensitive credentials, including those for major cloud providers (AWS, GCP, Azure), potentially granting attackers access to critical infrastructure and sensitive data. Even a short window of exposure can lead to widespread compromise if a large number of projects pull the malicious package.

## Recommendation

*   Immediately check if your projects installed `intercom/intercom-php` version 5.0.2 between 20:53 and 22:37 UTC on April 30, 2026, using `composer show intercom/intercom-php --version` as indicated in the overview.
*   If the project installed the malicious version, treat all credentials accessible from that environment as compromised and rotate them, as mentioned in the Workarounds section.
*   Clear the Composer cache using `composer clear-cache` to prevent further installations of the malicious package, as recommended in the Patches section.
*   Verify the commit hash in your `composer.lock` file against the malicious hash `e69bf4b3` and the clean hash `9371eba9`, as suggested in the Overview and Workarounds sections.
*   Deploy the Sigma rule `Detect Bun Execution` to identify instances where the Bun JavaScript runtime is executed, potentially indicating malicious activity from the dropper.
*   Enable process creation logging with command-line arguments to effectively utilize the `Detect Bun Execution` Sigma rule.
