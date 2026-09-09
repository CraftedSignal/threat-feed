---
title: Cortex XDR Broker VM Privilege Escalation Vulnerability
slug: 2026-09-cortex-xdr-broker-vm-priv-esc
description: A privilege escalation vulnerability (CVE-2026-0304) in Palo Alto Networks Cortex XDR Broker VM allows an authenticated, low-privileged attacker with man-in-the-middle positioning to execute arbitrary code as root.
date: "2026-09-09T18:58:54Z"
type: threat
types:
  - threat
severities:
  - medium
exploited: true
cpes:
  - cpe:2.3:a:palo_alto_networks:cortex_xdr_broker_vm:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - privilege-escalation
  - cortex-xdr
vendors:
  - Palo Alto Networks
products:
  - Cortex XDR Broker VM (< 32.0.52)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A privilege escalation vulnerability in Palo Alto Networks Cortex XDR Broker VM enables an authenticated low privileged user with man-in-the-middle (MitM) access to execute code with root privileges on the Broker VM.
    confidence_band: high
references:
  - https://security.paloaltonetworks.com/CVE-2026-0304
action_plan:
  priority: elevated
  owners:
    - IT Operations
  mitigation_plan:
    - priority: immediate
      action: Upgrade Cortex XDR Broker VM to version 32.0.52 or later.
      owner: IT Operations
      addresses: CVE-2026-0304
      evidence: This issue is fixed in Cortex XDR Broker VM 32.0.52, and all later Cortex XDR Broker VM versions.
---

Palo Alto Networks has disclosed a privilege escalation vulnerability, tracked as CVE-2026-0304, affecting the Cortex XDR Broker VM. The issue stems from improper neutralization of argument delimiters (CWE-88) in command processing, combined with path traversal (CAPEC-126). This vulnerability can be triggered when the Broker VM processes cloud-delivered mount actions. An attacker who is already authenticated as a low-privileged user and positioned to conduct a man-in-the-middle (MitM) attack can manipulate these commands to achieve root-level code execution on the appliance. The vulnerability affects versions of Cortex XDR Broker VM prior to 32.0.52. Palo Alto Networks reports no known in-the-wild exploitation.

## Impact

Successful exploitation of this vulnerability grants an attacker root privileges on the Cortex XDR Broker VM. This enables full control over the appliance, potentially allowing the attacker to intercept sensitive traffic, exfiltrate data, or further compromise the internal network segments where the Broker VM resides. The vulnerability affects all deployments that process cloud-delivered mount actions without specific configuration changes required to trigger the risk.

## Recommendation

Prioritize the upgrade of all Cortex XDR Broker VM instances to version 32.0.52 or later. If your organization does not have automatic upgrades enabled for the Broker VM, verify the current version on all internet-facing or high-exposure management appliances and initiate a manual update immediately. There are no known workarounds for this vulnerability.
