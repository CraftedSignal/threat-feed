---
title: Compromised node-ipc npm Package Steals Credentials
slug: 2026-05-node-ipc-supply-chain
description: Hackers injected credential-stealing malware into newly published versions of the node-ipc npm package in a supply chain attack, collecting cloud credentials, SSH keys, CI/CD secrets, and other sensitive data, exfiltrating it through DNS TXT queries.
date: "2026-05-15T17:12:42Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - supply-chain-attack
  - npm
  - infostealer
  - credential-theft
vendors:
  - npm
  - Microsoft
  - Amazon
  - Google
  - Oracle
  - DigitalOcean
  - GitHub
  - GitLab
products:
  - node-ipc
  - AWS
  - Azure
  - GCP
  - OCI
  - DigitalOcean
  - GitHub
  - Git CLI
  - GitLab
  - Microsoft Teams
  - Firefox
affected_os:
  - macos
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1609
    technique_name: Supply Chain Compromise
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1025
    technique_name: Data from Removable Media
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1071.004
    technique_name: 'Application Layer Protocol: DNS'
references:
  - https://www.bleepingcomputer.com/news/security/popular-node-ipc-npm-package-compromised-to-steal-credentials/
iocs:
  - type: domain
    value: sh[.]azurestaticprovider[.]net
  - type: domain
    value: bt[.]node[.]js
ioc_counts:
  domain: 2
rules:
  - title: Detect node-ipc Package Loading
    description: Detects loading of the compromised node-ipc package versions 9.1.6, 9.2.3, and 12.0.1
    platform: sigma
    severity: medium
    tactics:
      - initial_access
    techniques:
      - T1609
    data_sources:
      - process_creation
      - linux
  - title: Detect DNS TXT Exfiltration via Azure Static Provider
    description: Detects DNS TXT queries to sh[.]azurestaticprovider[.]net potentially indicating data exfiltration
    platform: sigma
    severity: high
    tactics:
      - exfiltration
    techniques:
      - T1071.004
    data_sources:
      - dns_query
      - windows
rules_count: 2
---

Hackers have compromised the node-ipc npm package, a popular inter-process communication module, to inject credential-stealing malware. This supply chain attack targets developers using the compromised versions: 9.1.6, 9.2.3, and 12.0.1. The malicious code resides within the CommonJS entrypoint (node-ipc.cjs) and automatically executes upon application loading. The malware, heavily obfuscated, fingerprints systems, collects sensitive information, compresses it, and exfiltrates it via DNS TXT queries. The compromise appears to stem from an external actor gaining access to the account of an inactive maintainer named 'atiertant.' This attack underscores the risks associated with supply chain vulnerabilities in open-source software.

## Attack Chain

1.  Attacker compromises the npm account of an inactive node-ipc maintainer ('atiertant').
2.  Attacker injects heavily obfuscated credential-stealing malware into node-ipc.cjs.
3.  Attacker publishes malicious versions of node-ipc (9.1.6, 9.2.3, 12.0.1) to the npm registry.
4.  Developers unknowingly download and integrate the compromised node-ipc versions into their projects.
5.  Upon application execution, the malware fingerprints the infected system.
6.  The malware collects sensitive information, including cloud credentials, SSH keys, CI/CD secrets, and other local files.
7.  The collected data is compressed into tar.gz archives.
8.  The compressed archives are exfiltrated via DNS TXT queries to a fake Azure-themed domain (sh[.]azurestaticprovider[.]net), ultimately reaching 'bt[.]node[.]js'.

## Impact

This supply chain attack allows attackers to steal sensitive credentials and secrets from compromised developer environments and applications. The stolen information includes cloud credentials for AWS, Azure, GCP, OCI, and DigitalOcean, as well as SSH keys, Kubernetes configurations, and API tokens for services like npm, GitHub, and GitLab. Successful exfiltration can lead to unauthorized access to cloud resources, source code repositories, and CI/CD pipelines, potentially affecting thousands of organizations relying on the node-ipc package. The malware avoids persistence and secondary payloads to focus on rapid credential theft.

## Recommendation

*   Immediately remove the affected node-ipc versions (9.1.6, 9.2.3, 12.0.1) from your projects and dependencies.
*   Rotate all potentially exposed secrets and credentials, including cloud credentials, SSH keys, API tokens, and database passwords.
*   Inspect lockfiles and npm caches for traces of the malicious packages.
*   Monitor DNS traffic for suspicious TXT queries to the domain sh[.]azurestaticprovider[.]net, which indicates potential data exfiltration.
*   Deploy the Sigma rule "Detect node-ipc Package Loading" to identify instances of the compromised package being loaded in your environment.
*   Deploy the Sigma rule "Detect DNS TXT Exfiltration via Azure Static Provider" to detect DNS queries associated with data exfiltration.
