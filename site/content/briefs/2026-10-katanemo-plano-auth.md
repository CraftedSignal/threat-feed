---
title: Unauthenticated Exposure of Envoy Admin Interface in Katanemo Plano
slug: 2026-10-katanemo-plano-auth
description: Katanemo Plano versions 0.4.37 and earlier contain a missing authentication vulnerability on the Envoy admin interface that allows unauthenticated remote attackers to exfiltrate LLM provider API keys.
date: "2026-10-11T16:02:59Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:katanemo:plano:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - exposure
  - envoy
  - credential-theft
vendors:
  - Katanemo
products:
  - Plano (<= 0.4.37)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Katanemo Plano contains a missing authentication vulnerability that allows unauthenticated network attackers to access the Envoy admin interface.
    confidence_band: high
cves:
  - id: CVE-2026-108863
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-108863
rules:
  - title: Detect Unauthorized Access to Envoy Admin Interface
    description: Detects unauthorized attempts to access the Envoy admin interface (/config_dump) which is vulnerable to CVE-2026-108863
    platform: sigma
    severity: high
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Network Security
  immediate_actions:
    - action: Apply network-level firewall restrictions to block traffic to TCP port 9901 from unauthorized segments.
      owner: Network Security
      due: 24h
      evidence: Source states Envoy admin interface is bound to all host interfaces.
  enrichment_needed:
    - item: Patched version availability
      owner: CTI
      reason: Ensure tracking of vendor updates to remediate the vulnerability permanently.
      evidence: NVD entry does not specify a fixed version.
  mitigation_plan:
    - priority: immediate
      action: Rotate all LLM provider API keys used within the Katanemo Plano environment.
      owner: IT Operations
      addresses: CVE-2026-108863
      evidence: Attackers can read configured LLM provider API keys in plaintext.
---

Katanemo Plano versions 0.4.37 and earlier contain a critical missing authentication vulnerability in its Envoy proxy deployment. The Envoy admin interface, which is typically used for diagnostic and configuration tasks, is improperly exposed and bound to all host interfaces on TCP port 9901. This configuration flaw allows any unauthenticated network attacker with connectivity to the interface to query the /config_dump endpoint. This endpoint returns the full proxy configuration in JSON format. Because Katanemo Plano stores LLM provider API keys as plaintext values within the WASM filter configuration, successful exploitation results in the immediate exfiltration of sensitive credentials used to interface with external Large Language Model services. This vulnerability poses a significant risk to organizations relying on Plano for LLM gateway orchestration, as the exposure of these keys could lead to unauthorized cost accumulation or data leakage via downstream service providers.

## Impact

Successful exploitation allows unauthenticated attackers to steal sensitive API credentials required to access and utilize external LLM providers. This effectively grants the attacker the ability to spoof the organization's identity when interacting with these services, leading to potential unauthorized charges or access to sensitive model interactions. The vulnerability impacts all deployments of Plano version 0.4.37 and older where the Envoy admin port 9901 is reachable via the network.

## Recommendation

* Restrict network access to TCP port 9901 immediately via host-based firewalls or network access control lists (NACLs) to ensure only authorized management workstations can access the Envoy admin interface.
* Monitor network traffic for inbound connections directed at TCP port 9901 from untrusted sources or internal segments not designated for administration.
* Rotate all LLM provider API keys configured within the Plano environment, as they must be assumed compromised if the instance has been exposed to an untrusted network.
* Upgrade all instances of Katanemo Plano to a patched version beyond 0.4.37 once released by the vendor.
