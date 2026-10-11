---
title: LlamaFarm Insecure Default Configuration and Unauthenticated API Access
slug: 2026-10-llamafarm-insecure-config
description: LlamaFarm versions 0.0.34 and earlier contain an insecure default configuration that binds an unauthenticated FastAPI service to all network interfaces, allowing remote attackers to exfiltrate API keys and manipulate project data.
date: "2026-10-11T14:01:57Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:llamafarm:llamafarm:*:*:*:*:*:*:*:*
vendors:
  - LlamaFarm
products:
  - LlamaFarm (<= 0.0.34)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Network-adjacent attackers can call the project and dataset management API to read stored provider API keys, modify projects, trigger ingestion, and irreversibly delete projects.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108760
rules:
  - title: Detect LlamaFarm API Access from Remote Sources
    description: Detects unauthorized access attempts to the LlamaFarm management API (port 14345) from non-local IP addresses, which may indicate exploitation of CVE-2026-108760
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - network_connection
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade LlamaFarm to a version later than 0.0.34
      owner: IT Operations
      due: 48h
      evidence: LlamaFarm through 0.0.34 contains an insecure default configuration
  mitigation_plan:
    - priority: immediate
      action: Restrict access to TCP port 14345 using host-based firewalls
      owner: IT Operations
      addresses: CVE-2026-108760
      evidence: binds its unauthenticated FastAPI server to 0.0.0.0
---

LlamaFarm versions through 0.0.34 suffer from an insecure default configuration that exposes the internal FastAPI management server to all network interfaces by binding it to 0.0.0.0 on port 14345. Additionally, the lf command-line interface fails to honor host overrides, preventing administrators from restricting access to the local loopback interface. This vulnerability allows network-adjacent attackers to interact directly with the project and dataset management API without any form of authentication. By sending crafted HTTP requests, an attacker can exfiltrate sensitive provider API keys stored within the application, modify existing projects, trigger unauthorized data ingestion processes, or perform destructive actions such as the irreversible deletion of projects. This exposure creates significant risk for organizations using LlamaFarm in environments accessible from broader network segments.

## Impact

Successful exploitation allows unauthorized third parties to gain full control over the LlamaFarm application. The impact includes the exfiltration of sensitive third-party API credentials, the potential poisoning or unauthorized modification of datasets, and data loss due to the ability to delete projects. Given the nature of project management APIs, this could result in significant operational disruption and compromise of upstream services authenticated by the exfiltrated keys.

## Recommendation

- Upgrade LlamaFarm to the latest version immediately to remediate the default binding configuration.
- Implement network segmentation to ensure port 14345 is not reachable from untrusted network segments.
- Apply host-based firewall rules to explicitly restrict access to port 14345 to known authorized management IP addresses.
- Audit logs for the LlamaFarm API endpoint for any unauthorized POST, PUT, or DELETE requests from unexpected source IP addresses.
