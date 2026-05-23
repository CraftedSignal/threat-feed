---
title: Laravel Lang Packages Hijacked in Credential-Stealing Supply Chain Attack
slug: 2026-05-laravel-supply-chain
description: Attackers compromised Laravel Lang packages by rewriting GitHub tags, distributing a credential-stealing malware targeting cloud credentials, secrets, keys, browser data, and cryptocurrency wallets across Windows, Linux, and macOS systems.
date: "2026-05-23T20:51:26Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain-attack
  - credential-theft
  - infostealer
  - composer
  - php
  - github
vendors:
  - Laravel
products:
  - laravel-lang/lang
  - laravel-lang/http-statuses
  - laravel-lang/attributes
  - laravel-lang/actions
affected_os:
  - Windows
  - MacOS
  - Linux
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1199
    technique_name: Supply Chain Compromise
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
  - https://www.bleepingcomputer.com/news/security/laravel-lang-packages-hijacked-to-deploy-credential-stealing-malware/
iocs:
  - type: domain
    value: flipboxstudio[.]info
ioc_counts:
  domain: 1
rules:
  - title: Detect PHP Dropper Downloading Payload
    description: Detects a PHP script downloading a payload from a remote URL, indicative of dropper behavior.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1199
    data_sources:
      - webserver
  - title: Detect Windows Executable Dropped by PHP
    description: Detects the creation of an executable file in the %TEMP% directory by a PHP process.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
    techniques:
      - T1027
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

A supply chain attack compromised the Laravel Lang localization packages, impacting developers using Composer to manage dependencies. Starting around May 22, 2026, attackers rewrote GitHub tags across four repositories maintained by the Laravel Lang organization instead of publishing new malicious versions. This allowed the attackers to distribute malicious code through existing, seemingly legitimate release tags. The affected packages are laravel-lang/lang, laravel-lang/http-statuses, laravel-lang/attributes, and possibly laravel-lang/actions. The Laravel Lang packages are third-party localization packages and are not part of the official Laravel project. Security firms estimate that hundreds of historical versions may have been affected by this campaign.

## Attack Chain

1. Attackers compromised a GitHub account with organization-wide push access for the Laravel Lang organization.
2. The attackers rewrote existing Git tags in the affected repositories (laravel-lang/lang, laravel-lang/http-statuses, laravel-lang/attributes, laravel-lang/actions) to point to malicious commits.
3. Developers unknowingly installed compromised Laravel Lang packages via Composer, pulling down the malicious commits.
4. The malicious commits introduced a file named `src/helpers.php`, which was automatically loaded due to configuration in `composer.json`.
5. `src/helpers.php` acted as a dropper, downloading a second-stage PHP payload from the C2 server at flipboxstudio[.]info.
6. The downloaded PHP payload functioned as a cross-platform credential stealer, targeting cloud credentials, Kubernetes secrets, Vault tokens, Git credentials, CI/CD secrets, SSH keys, browser data, cryptocurrency wallets, password managers, VPN configurations, and local `.env` configuration files.
7. On Windows systems, the PHP payload extracted and executed a base64-encoded executable named 'DebugElevator' to steal browser credentials.
8. The collected sensitive data was encrypted and sent back to the C2 server at flipboxstudio[.]info.

## Impact

This supply chain attack exposed developers using the affected Laravel Lang packages to credential-stealing malware. The malware targeted a wide range of sensitive information, including cloud credentials, secrets, and keys. Successful exfiltration could lead to unauthorized access to cloud infrastructure, code repositories, and other sensitive systems. Compromised credentials can be used for further attacks, data breaches, or financial theft. While the exact number of affected developers remains unknown, the popularity of Laravel Lang suggests a potentially wide impact.

## Recommendation

*   Review installed versions of Laravel Lang packages and compare against a known-good manifest to identify compromised versions.
*   Rotate all potentially exposed credentials, including cloud credentials, API keys, and secrets, especially if using any of the affected Laravel Lang packages.
*   Inspect systems for indicators of compromise, such as outbound connections to the C2 domain flipboxstudio[.]info.
*   Deploy the Sigma rule "Detect PHP Dropper Downloading Payload" to identify similar dropper behavior in web server logs.
*   Deploy the Sigma rule "Detect Windows Executable Dropped by PHP" to identify the 'DebugElevator' infostealer execution.
