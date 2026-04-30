---
title: Mini Shai-Hulud Supply Chain Attack Targets SAP NPM Packages
slug: 2026-04-mini-shai-hulud
description: The Mini Shai-Hulud campaign injected malicious code into SAP NPM packages, targeting credentials and cloud secrets related to SAP Cloud Application Programming (CAP) and SAP cloud deployment workflows, exfiltrating data through public GitHub repositories.
date: "2026-04-30T14:27:36Z"
type: threat
types:
  - threat
severities:
  - critical
actors:
  - TeamPCP
tags:
  - supply-chain
  - npm
  - sap
  - credential-theft
vendors:
  - SAP
  - GitHub
products:
  - Cloud Application Programming (CAP)
  - Cloud MTA Build Tool
  - '@cap-js/db-service'
  - '@cap-js/postgres'
  - '@cap-js/sqlite'
  - github.com
mitre_ttps:
  - tactic_id: TA0009
    tactic_name: Supply Chain Compromise
    technique_id: T1195
    technique_name: Supply Chain Compromise
references:
  - https://www.securityweek.com/sap-npm-packages-targeted-in-supply-chain-attack/
rules:
  - title: Detect Bun Execution From NPM Package
    description: Detects the execution of the Bun binary from an NPM package, which is an indicator of the Mini Shai-Hulud attack.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1213.002
    data_sources:
      - process_creation
      - windows
  - title: GitHub Repository Description - Mini Shai-Hulud Exfiltration
    description: Detects GitHub repositories created with the specific description used by the Mini Shai-Hulud malware for exfiltrating stolen data.
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1567.002
    data_sources:
      - webserver
      - linux
rules_count: 2
---

The Mini Shai-Hulud campaign, active as of April 2026, targets SAP NPM packages used in the SAP Cloud Application Programming (CAP) ecosystem and SAP cloud deployment workflows. Four package versions were compromised: `mbt 1.2.48`, `@cap-js/db-service 2.10.1`, `@cap-js/postgres 2.2.2`, and `@cap-js/sqlite 2.2.2`. These packages, with over 500,000 combined weekly downloads, are essential for SAP's Cloud MTA Build Tool and database services for CAP software. The attackers injected a preinstall script that fetches and executes a Bun binary, bypassing security monitoring. The malicious versions were available for a short window of 2-4 hours before being unpublished and superseded by clean versions. Wiz attributes this activity to TeamPCP due to a shared RSA public key used to encrypt the exfiltrated secrets.

## Attack Chain

1.  The attacker compromises an NPM token, possibly exposed through CircleCI.
2.  The attacker injects a malicious `preinstall` script into the targeted SAP NPM packages (`mbt`, `@cap-js/db-service`, `@cap-js/postgres`, `@cap-js/sqlite`).
3.  When a user installs the compromised package, the `preinstall` script executes.
4.  The script fetches a Bun ZIP archive from a GitHub repository.
5.  The script extracts the Bun archive and executes the included Bun binary.
6.  The Bun binary steals local credentials, GitHub and NPM tokens, AWS, Azure, GCP, GitHub Action, and Kubernetes secrets.
7.  The stolen data is exfiltrated to public GitHub repositories with the description "A Mini Shai-Hulud has Appeared".
8.  The malware propagates by modifying package tarballs, updating versions, repackaging them, and publishing them using stolen GitHub Actions tokens.

## Impact

The Mini Shai-Hulud attack poses a significant threat to developers and organizations using SAP CAP, a framework for S/4HANA extensions, Fiori app backends, MTAs, and integration flows. With over 500,000 weekly downloads of the affected packages, a large number of systems could have been affected. Successful exploitation allows attackers to steal sensitive credentials and cloud secrets, potentially leading to unauthorized access to critical SAP systems, cloud infrastructure, and source code repositories. This access could be used for further malicious activities, including data breaches, financial fraud, and supply chain compromise.

## Recommendation

*   Organizations using SAP Business Technology Platform workflows, SAP CAP, or MTA-based deployment pipelines should immediately check if they installed the malicious package versions (`mbt 1.2.48`, `@cap-js/db-service 2.10.1`, `@cap-js/postgres 2.2.2`, `@cap-js/sqlite 2.2.2`) during the exposure window.
*   Implement network monitoring rules to detect connections to unusual GitHub repositories created to host stolen data. Monitor for repositories with the description "A Mini Shai-Hulud has Appeared".
*   Monitor process execution for the execution of `bun` binaries in unusual or unexpected locations to identify systems where compromised packages were installed. Deploy the Sigma rule `Detect Bun Execution From NPM Package` to detect this behavior.
