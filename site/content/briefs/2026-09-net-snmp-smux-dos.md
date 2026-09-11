---
title: Net-SNMP Denial of Service via SMUX Module
slug: 2026-09-net-snmp-smux-dos
description: An unauthenticated denial of service vulnerability in Net-SNMP versions up to 5.9.5.2 allows remote attackers to hang the snmpd process by initiating idle connections to the SMUX module.
date: "2026-09-11T13:13:17Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:net_snmp:net_snmp:*:*:*:*:*:*:*:*
tags:
  - denial-of-service
  - network-infrastructure
  - vulnerability
vendors:
  - Net-SNMP
products:
  - Net-SNMP (<= 5.9.5.2)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1499
    technique_name: Endpoint Denial of Service
    evidence: An unauthenticated remote client can connect to the SMUX listener and send no data, causing the single-threaded snmpd main loop to block indefinitely and suspend all SNMP processing.
    confidence_band: high
cves:
  - id: CVE-2026-89147
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-89147
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Network Security
  immediate_actions:
    - action: Disable SMUX module in snmpd.conf if not strictly required for infrastructure integration
      owner: Network Security
      due: 48h
      evidence: Source describes vulnerability in SMUX module
  mitigation_plan:
    - priority: immediate
      action: Upgrade Net-SNMP to a patched version beyond 5.9.5.2
      owner: IT Operations
      addresses: CVE-2026-89147
      evidence: Source identifies vulnerability in versions through 5.9.5.2
---

Net-SNMP versions through 5.9.5.2 are susceptible to a critical denial of service vulnerability within the SMUX (SNMP Multiplexing) protocol module. The issue originates from the smux_accept() function, which performs an unauthenticated blocking read on incoming connections without implementing a timeout mechanism. Because the primary snmpd process operates in a single-threaded architecture, an attacker can trigger this flaw by establishing a connection to the SMUX listener and intentionally sending no data. This forces the process to block indefinitely while awaiting input, effectively suspending all SNMP monitoring and management capabilities for the target device. This vulnerability presents a high impact to network availability as it allows unauthenticated remote actors to disable monitoring instrumentation without requiring complex payloads or elevated privileges.

## Impact

Successful exploitation results in a complete denial of service for SNMP management services on the affected system. This disruption prevents administrators from gathering performance telemetry, monitoring device health, or performing remote configuration management. The vulnerability targets any system running Net-SNMP with the SMUX module enabled, impacting enterprise network infrastructure and server environments.

## Recommendation

Prioritize upgrading to a version of Net-SNMP where the smux_accept() timeout issue is addressed. Until patching is completed, identify and disable the SMUX protocol on all internet-facing or unauthorized SNMP management endpoints to reduce the attack surface.
