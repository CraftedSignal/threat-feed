---
title: Detection of macOS Network Share Discovery via Enumeration Utilities
slug: 2026-10-macos-network-share-discovery
description: Adversaries leverage native macOS utilities such as smbutil and showmount to perform internal network reconnaissance by discovering available SMB and NFS shares.
date: "2026-10-12T17:52:26Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - macos
  - reconnaissance
  - discovery
  - post-exploitation
affected_os:
  - macOS
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1135
    technique_name: Network Share Discovery
    evidence: Identifies execution of network share enumeration commands (smbutil, showmount) that can be leveraged by adversaries to discover accessible SMB and NFS resources.
    confidence_band: high
references:
  - https://osquery.readthedocs.io/en/stable/deployment/process-auditing/
  - https://leopard-adc.pepas.com/documentation/Darwin/Reference/ManPages/man8/showmount.8.html
  - https://www.unix.com/man_page/osx/1/smbutil/
  - https://github.com/redcanaryco/atomic-red-team/blob/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics/T1135/T1135.yaml
rules:
  - title: Detect macOS Network Share Discovery
    description: Detects the execution of smbutil or showmount utilities which are used for network share enumeration
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1135
    data_sources:
      - process_creation
      - macos
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection logic to SIEM and validate against baseline administrative activity
      owner: Detection Engineering
      due: 7d
      evidence: Source provides detection search logic for process enumeration
  hunt_leads:
    - lead: Search for historical execution of smbutil or showmount in process logs
      technique_id: T1135
      data_needed:
        - Process command line logs
      priority: medium
      confidence: medium
      disposition: convert_to_detection
      evidence: Standard reconnaissance toolset on macOS
---

Adversaries targeting macOS environments frequently perform internal reconnaissance to identify accessible network resources that may contain sensitive data or facilitate further lateral movement. The use of built-in system utilities such as 'smbutil' and 'showmount' allows attackers to enumerate SMB and NFS network shares respectively without deploying additional custom binaries. This activity often occurs during the post-exploitation phase, where the attacker is mapping the local network topology and identifying target systems or file stores. Detecting this behavior is essential for security operations centers, as the execution of these utilities is rarely required for routine end-user operations. Defenders should focus on monitoring process creation events linked to these utilities, particularly when invoked from non-standard paths or by unexpected user accounts, to identify malicious internal discovery efforts.

## Impact

Successful internal reconnaissance allows adversaries to identify high-value targets for data exfiltration or lateral movement within a corporate network. If an attacker identifies sensitive file shares, it could lead to unauthorized access to proprietary information, credentials, or system configurations, potentially resulting in a significant data breach.

## Recommendation

* Deploy process auditing on macOS endpoints using Endpoint Security frameworks and osquery to capture execution telemetry for 'smbutil' and 'showmount'.
* Implement the provided detection logic to alert on the execution of these utilities and tune out known administrative baselines in your environment.
* Investigate alerts by pivoting to user and host telemetry to determine if the execution of these tools aligns with authorized troubleshooting activities or indicates unauthorized reconnaissance.
