---
brief_id: brief-2026-11-18-linux-net-recon
event_id: brief-2026-11-18-linux-net-recon
revision: 1
activity_at: "2026-11-18T13:49:48Z"
title: Linux Network Service Scanning Tools Execution
slug: 2026-11-linux-net-recon
description: This detection rule identifies the execution of various network scanning and reconnaissance tools on Linux systems that can be used for the enumeration of local or remote network services.
date: "2026-11-18T13:49:48Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
tags:
  - attack.discovery
  - attack.t1046
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0007
    tactic_name: Discovery
    technique_id: T1046
    technique_name: Network Service Discovery
    evidence: Detects execution of network scanning and reconnaissance tools. These tools can be used for the enumeration of local or remote network services.
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_susp_network_utilities_execution.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1046/T1046.md
  - https://github.com/projectdiscovery/naabu
  - https://github.com/Tib3rius/AutoRecon
rules:
  - title: Linux Network Service Scanning Tools Execution
    description: Detects execution of network scanning and reconnaissance tools. These tools can be used for the enumeration of local or remote network services.
    platform: sigma
    severity: low
    tactics:
      - discovery
    techniques:
      - T1046
    data_sources:
      - process_creation
      - linux
rules_count: 1
---

## Overview

Certain network utilities and scanning tools on Linux can be used for the enumeration of local or remote network services. This detection monitors for the execution of these tools to identify reconnaissance activity.

## Attack Chain

Discovery (T1046): These tools are used for network service discovery, which is a common activity during the reconnaissance phase of an attack.

## Impact

Successful use of these tools allows an adversary to identify active services and open ports, potentially revealing attack vectors within the local or remote network.

## Recommendation

Monitor the execution of network utilities and scanners. Distinguish between legitimate administrative network diagnostic activities and unauthorized reconnaissance.
