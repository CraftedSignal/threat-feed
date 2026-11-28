---
brief_id: brief-2026-11-28-macos-network-share-discovery
event_id: brief-2026-11-28-macos-network-share-discovery
revision: 1
activity_at: "2026-11-28T20:42:55Z"
title: MacOS Network Share Discovery via Administrative Utilities
slug: 2026-11-macos-network-share-discovery
description: This detection identifies potential internal reconnaissance activity on macOS by monitoring for the execution of native tools like smbutil and showmount, which can be used to enumerate network shares.
date: "2026-11-28T20:42:55Z"
type: advisory
types:
  - advisory
severities:
  - medium
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
tags:
  - macos
  - discovery
  - endpoint
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1135
    technique_name: Network Share Discovery
    evidence: Identifies execution of network share enumeration commands (smbutil, showmount) that can be leveraged by adversaries to discover accessible SMB and NFS resources, supporting internal reconnaissance and potential lateral movement.
    confidence_band: high
references:
  - https://github.com/splunk/security_content/blob/main/detections/endpoint/macos_network_share_discovery.yml
  - https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
  - https://leopard-adc.pepas.com/documentation/Darwin/Reference/ManPages/man8/showmount.8.html
  - https://www.unix.com/man_page/osx/1/smbutil/
rules:
  - title: MacOS Network Share Enumeration
    description: Detects the execution of macOS native tools smbutil and showmount, which can be used for network share reconnaissance.
    platform: sigma
    severity: medium
    tactics:
      - discovery
    techniques:
      - T1135
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - Detection Engineering
    - SOC
  immediate_actions:
    - action: Deploy Sigma rule to monitor for execution of smbutil and showmount on macOS fleets.
      owner: Detection Engineering
      due: 72h
      evidence: Source content identifies these specific processes as indicators of network share discovery.
  hunt_leads:
    - lead: Identify anomalous execution of network utility binaries across macOS fleet.
      technique_id: T1135
      data_needed:
        - Endpoint process logs
        - Osquery results
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Source suggests these tools are commonly used for reconnaissance.
---

## Overview

Adversaries targeting macOS systems may perform internal reconnaissance by enumerating accessible network resources. The utilities smbutil and showmount are native macOS tools that can be leveraged to discover SMB and NFS shares respectively. Monitoring the execution of these processes can help detect potential pre-exploitation reconnaissance or lateral movement attempts within an environment.

## Recommendation

- Deploy the TA-OSquery application to your indexers and universal forwarders to collect process data from endpoint security logs.
- Enable process auditing on macOS endpoints to capture process creation events for smbutil and showmount.
- Baseline administrative activity within your environment to tune out false positives associated with legitimate troubleshooting workflows.
- Review the listed references for detailed configuration steps on setting up process auditing with osquery on macOS.
