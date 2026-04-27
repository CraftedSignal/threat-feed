---
title: Azure SRE Agent Improper Authentication Vulnerability (CVE-2026-32173)
slug: 2026-04-azure-sre-auth-bypass
description: An improper authentication vulnerability (CVE-2026-32173) in the Azure SRE Agent allows an unauthorized attacker to disclose sensitive information over the network, potentially leading to data breaches or further compromise.
date: "2026-04-03T00:16:04Z"
severities:
  - high
tags:
  - azure
  - sre
  - authentication
  - information-disclosure
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
cves:
  - id: CVE-2026-32173
    cvss: 8.6
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-32173
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-32173
rules:
  - title: Detect Azure SRE Agent Information Disclosure Attempt
    description: Detects potential attempts to exploit CVE-2026-32173 by monitoring network requests to the Azure SRE Agent.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
      - windows
  - title: Detect Azure SRE Agent Information Disclosure Attempt - Process Creation
    description: Detects potential attempts to exploit CVE-2026-32173 by monitoring process creation related to the Azure SRE Agent.
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - process_creation
      - windows
rules_count: 2
---

CVE-2026-32173 identifies a critical improper authentication vulnerability within the Azure SRE Agent. This flaw enables an unauthenticated attacker to potentially gain unauthorized access to sensitive information traversing the network. The vulnerability was published on 2026-04-02 and has a CVSS v3.1 score of 8.6, indicating a high severity.  The vulnerability affects systems utilizing the Azure SRE Agent and could expose confidential data to unauthorized parties. Successful exploitation…
