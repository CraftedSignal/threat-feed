---
brief_id: brief-2026-10-25-araxis-merge-dpapi-exposure
event_id: brief-2026-10-25-araxis-merge-dpapi-exposure
revision: 1
activity_at: "2026-10-25T03:40:33Z"
title: 'Araxis Merge: Local credential decryption via DPAPI (CVE-2026-92680)'
slug: 2026-10-araxis-merge-dpapi-exposure
description: Araxis Merge for Windows stores server credentials using DPAPI with NULL entropy, allowing an attacker with local user access to decrypt and extract stored credentials from the registry.
date: "2026-10-25T03:40:33Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation
cpes:
  - cpe:2.3:a:araxis:merge:*:*:*:*:*:windows:*:*
tags:
  - credential-theft
  - dpapi
  - windows
  - local-exploitation
vendors:
  - Araxis Ltd.
products:
  - Araxis Merge for Windows (2011.4074 - 2026.0)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Araxis Merge for Windows stores server credentials with DPAPI with pOptionalEntropy set to NULL.
    confidence_band: high
cves:
  - id: CVE-2026-92680
    cvss: 5.5
    epss: 0.00165
    kev_status: "false"
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GREPSTRENGTH-CVE-2026-92680
  - https://grepstrength.com/research/araxis-merge
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-GREPSTRENGTH-CVE-2026-92680&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Access to Araxis Merge Registry Credentials
    description: Detects processes querying the registry key containing Araxis Merge passwords, which may indicate attempted credential extraction
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552.001
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Araxis Merge to version 2026.1
      owner: IT Operations
      due: 7d
      evidence: Fixed in 2026.1
  hunt_leads:
    - lead: Identify processes reading the Araxis registry hive using EDR registry monitoring
      technique_id: T1552.001
      data_needed:
        - Registry read events
      priority: high
      confidence: high
      disposition: convert_to_detection
      evidence: The PoC provided targets specific registry entries for credential decryption.
  mitigation_plan:
    - priority: immediate
      action: Upgrade to version 2026.1
      owner: IT Operations
      addresses: CVE-2026-92680
      evidence: Vendor advisory Merge-SA-26-00
---

Araxis Merge for Windows versions 2011.4074 through 2026.0 contain a vulnerability (CVE-2026-92680) in how server credentials are stored. The application utilizes the Windows Data Protection API (DPAPI) with a NULL value for the optional entropy parameter, rendering the encryption ineffective against any process executing within the same user security context. This allows an authenticated local user to programmatically access and decrypt credentials stored in the registry path `HKCU\Software\Araxis\Merge\7.1\Passwords`.

## Impact
Successful exploitation allows for the recovery of plaintext credentials used by Araxis Merge to connect to remote servers. This impact is limited to the local user context; an attacker must already have the ability to execute code as the target user.

## Recommendation
- Upgrade Araxis Merge for Windows to version 2026.1 or later to implement secure credential storage.
- Review security logs for anomalous execution of scripts or tools attempting to query the specified registry key.
- Audit user-level permissions to ensure that only authorized processes and users can access sensitive application registry hives.
