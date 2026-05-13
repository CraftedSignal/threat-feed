---
title: CVE-2026-0245 Prisma Access Agent Information Disclosure Vulnerability
slug: 2026-05-prisma-access-info-disclosure
description: CVE-2026-0245 describes multiple information disclosure vulnerabilities in Palo Alto Networks Prisma Access Agent before version 26.2.1 on macOS and Windows, allowing a local user to access sensitive configuration data and credentials.
date: "2026-05-13T16:08:37Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cve-2026-0245
  - information-disclosure
  - prisma-access-agent
vendors:
  - Palo Alto Networks
products:
  - Prisma Access Agent
affected_os:
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1082
    technique_name: Data Source Discovery
references:
  - https://security.paloaltonetworks.com/CVE-2026-0245
rules:
  - title: Detect Suspicious Prisma Access Agent Configuration Access
    description: Detects suspicious access to Prisma Access Agent configuration files that may indicate CVE-2026-0245 exploitation
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1082
    data_sources:
      - file_event
      - windows
rules_count: 1
---

Palo Alto Networks has disclosed CVE-2026-0245, a set of information disclosure vulnerabilities affecting Prisma Access Agent versions prior to 26.2.1 on macOS and Windows. A local attacker with low privileges could potentially exploit these vulnerabilities to gain access to sensitive configuration data and credentials stored by the agent. The Prisma Access Agent versions running on Linux, Android, ChromeOS, and iOS are not affected. Palo Alto Networks is not aware of any malicious exploitation of these issues.

## Attack Chain

1.  A local user gains access to a system with a vulnerable version of Prisma Access Agent installed (versions < 26.2.1 on macOS or Windows).
2.  The attacker leverages a low-complexity attack vector to interact with the Prisma Access Agent.
3.  Due to insufficient access controls or data protection mechanisms, the attacker is able to access sensitive configuration files or memory regions used by the agent.
4.  The attacker successfully extracts sensitive information, which may include credentials, API keys, or other configuration parameters.
5.  The attacker analyzes the disclosed data to identify valuable assets or potential attack vectors within the organization's network.
6.  The attacker may use the stolen credentials to impersonate legitimate users or services, gaining unauthorized access to protected resources.

## Impact

Successful exploitation of CVE-2026-0245 allows a local attacker to access sensitive configuration data and credentials stored by the Prisma Access Agent. This information could be used to gain unauthorized access to the organization's network or cloud resources, potentially leading to data breaches, service disruptions, or other security incidents.

## Recommendation

*   Upgrade Prisma Access Agent to version 26.2.1 or later on macOS and Windows systems to remediate CVE-2026-0245.
*   Monitor systems for unauthorized access to Prisma Access Agent configuration files or memory regions.
*   Deploy the Sigma rule `Detect Suspicious Prisma Access Agent Configuration Access` to detect potential exploitation attempts.
