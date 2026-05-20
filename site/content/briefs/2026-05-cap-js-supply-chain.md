---
title: Compromised @cap-js Packages Lead to Credential Theft and Self-Propagation
slug: 2026-05-cap-js-supply-chain
description: Compromised versions of `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, and `@cap-js/db-service@2.10.1` were published, leading to credential harvesting and attempted self-propagation; upgrade immediately and rotate credentials.
date: "2026-05-20T15:34:11Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - supply-chain
  - credential-theft
  - npm
products:
  - '@cap-js/sqlite'
  - '@cap-js/postgres'
  - '@cap-js/db-service'
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1199
    technique_name: Trusted Relationship
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1199
    technique_name: Trusted Relationship
references:
  - https://github.com/advisories/GHSA-pvw4-cvr4-97p8
rules:
  - title: Detect Potential Credential Access via Package Installation
    description: Detects suspicious processes spawned after installation of the compromised npm package which may indicate credential harvesting activity following CVE-2026-46421.
    platform: sigma
    severity: high
    tactics:
      - credential_access
      - persistence
    techniques:
      - T1199
    data_sources:
      - process_creation
      - windows
  - title: Detect access to common credential stores post npm install
    description: Detects attempts to read credential files or environment variables after installation of a suspicious npm package, indicating potential post-CVE-2026-46421 activity.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1003
    data_sources:
      - file_event
      - windows
rules_count: 2
---

On April 29, 2026, three malicious versions of `@cap-js` packages were published to the npm registry: `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, and `@cap-js/db-service@2.10.1`. These compromised packages contained malicious code designed to harvest credentials from the infected machine, including npm tokens, cloud provider credentials, SSH keys, and GitHub PATs. Additionally, the packages attempted to self-propagate to other systems. Defenders should immediately upgrade affected packages and rotate any credentials accessible on machines where these versions were installed. The vulnerability is tracked as CVE-2026-46421.

## Attack Chain

1. Attacker gains access to the package maintainer's npm account.
2. Attacker injects malicious code into `@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, and `@cap-js/db-service@2.10.1`.
3. Attacker publishes the compromised versions to the npm registry.
4. Developers unknowingly install the compromised packages as dependencies in their projects using `npm install`.
5. Upon installation, the malicious code executes, harvesting credentials from the affected system.
6. The malicious code collects npm tokens, cloud provider credentials, SSH keys, and GitHub PATs.
7. The compromised packages attempt to self-propagate to other systems, potentially spreading the compromise further.
8. Stolen credentials are used to compromise other systems or services.

## Impact

Compromised versions of the `@cap-js` packages led to the potential theft of sensitive credentials, including npm tokens, cloud provider credentials, SSH keys, and GitHub PATs. The self-propagation capability further exacerbates the impact, allowing the attacker to potentially compromise additional systems and services. If the attack succeeds, organizations risk data breaches, unauthorized access to critical infrastructure, and supply chain compromise impacting downstream users.

## Recommendation

*   Upgrade to `@cap-js/sqlite` >= 2.4.0, `@cap-js/postgres` >= 2.3.0, `@cap-js/db-service` >= 2.11.0 to remediate the vulnerability as documented in GHSA-pvw4-cvr4-97p8.
*   Rotate all credentials (npm tokens, cloud provider credentials, SSH keys, GitHub PATs) accessible on any machine where the compromised versions (`@cap-js/sqlite@2.2.2`, `@cap-js/postgres@2.2.2`, `@cap-js/db-service@2.10.1`) were installed.
*   Deploy the following Sigma rule to detect potential post-compromise activity related to credential access and exfiltration on affected systems.
