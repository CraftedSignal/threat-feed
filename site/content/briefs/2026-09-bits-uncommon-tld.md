---
title: Abuse of BITS Jobs via Suspicious or Uncommon Remote Endpoints
slug: 2026-09-bits-uncommon-tld
description: Adversaries utilize the Background Intelligent Transfer Service (BITS) to execute or stage malicious payloads from uncommon or suspicious remote domains to evade detection.
date: "2026-09-01T12:16:50Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - persistence
  - execution
  - bits
  - windows
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1197
    technique_name: BITS Jobs
    evidence: Adversaries may abuse BITS jobs to persistently execute or clean up after malicious payloads.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/builtin/bits_client/win_bits_client_new_transfer_via_uncommon_tld.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1197/T1197.md
rules:
  - title: BITS Transfer Job With Uncommon Or Suspicious Remote TLD
    description: Detects a suspicious download using the BITS client from a FQDN that is unusual to identify potential payload staging.
    platform: sigma
    severity: medium
    tactics:
      - execution
      - persistence
      - stealth
    techniques:
      - T1197
    data_sources:
      - process_creation
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
  immediate_actions:
    - action: Enable Microsoft-Windows-BITS-Client/Operational log to support visibility into BITS job creation
      owner: IT Operations
      due: 48h
  hunt_leads:
    - lead: Identify all BITS jobs created in the last 30 days that pull from domains not matching the exclusion list
      technique_id: T1197
      data_needed:
        - Event ID 16403 logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: BITS jobs are a known persistence mechanism for payloads
---

The Background Intelligent Transfer Service (BITS) is a legitimate Windows component designed to facilitate asynchronous file transfers between a client and a server. Threat actors frequently abuse this service to download malicious payloads or exfiltrate data, leveraging its capability to operate in the background and survive system reboots. This behavior provides a persistence and execution vector that is often overlooked by security teams.

By monitoring for BITS transfer jobs that communicate with remote domains not typically associated with trusted software updates or corporate CDN infrastructure, defenders can identify suspicious staging activity. This technique allows attackers to mask their malicious traffic within the noise of standard Windows background processes, necessitating granular filtering of expected domain patterns.

## Impact

Successful abuse of BITS enables attackers to maintain persistence on target systems, download additional stages of malware, or perform unauthorized data exfiltration. Because BITS transfers are managed by the Windows service controller, they may bypass certain network security controls that only inspect user-initiated traffic. This activity is observed in various threat campaigns that focus on staging secondary payloads post-initial access.

## Recommendation

Detection engineering teams should focus on identifying BITS jobs created against unusual domains.

* Deploy the provided Sigma rule to identify new BITS transfer jobs directed toward non-standard or uncommon remote endpoints.
* Establish a baseline of known-good, BITS-leveraging update servers in the organization to tune the detection logic and reduce false positives.
* Enable Microsoft-Windows-BITS-Client/Operational logging to capture the necessary events for monitoring BITS activity.
