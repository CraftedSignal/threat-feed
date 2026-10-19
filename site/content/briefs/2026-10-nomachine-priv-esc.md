---
title: Multiple Privilege Escalation Vulnerabilities in NoMachine
slug: 2026-10-nomachine-priv-esc
description: NoMachine software contains multiple vulnerabilities that permit a local attacker to escalate privileges to higher authority levels on the affected host.
date: "2026-10-19T14:07:44Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - privilege-escalation
  - windows
  - linux
  - macos
vendors:
  - NoMachine
products:
  - NoMachine
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Ein lokaler Angreifer kann mehrere Schwachstellen in NoMachine ausnutzen, um seine Privilegien zu erhöhen.
    confidence_band: high
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-4014
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Audit environment for all installed NoMachine versions and patch to the latest version provided by the vendor.
      owner: IT Operations
      due: 48h
      evidence: NoMachine software contains multiple vulnerabilities that can be exploited by a local attacker.
  mitigation_plan:
    - priority: immediate
      action: Upgrade all NoMachine software to the latest patched version.
      owner: IT Operations
      addresses: NoMachine privilege escalation
      evidence: BSI Security Advisory WID-SEC-2026-4014
---

NoMachine has reported multiple vulnerabilities affecting their remote access software suite. These flaws allow a local attacker, who already possesses low-privileged access to the target machine, to escalate their privileges to those of a more privileged user or system account. This class of vulnerability is significant because it allows a malicious actor to bypass standard operating system access controls, potentially gaining full control over the compromised system. The vulnerabilities affect NoMachine installations across Windows, Linux, and macOS platforms. Defenders should ensure all NoMachine clients and server components are updated to the latest available versions released by the vendor to mitigate the risk of local exploitation.

## Impact

Successful exploitation of these vulnerabilities allows a local attacker to elevate their privileges, potentially gaining administrative or root-level access to the system. This level of access grants the attacker the ability to install malicious software, exfiltrate sensitive data, or disable security controls. While these vulnerabilities require local access, they significantly lower the bar for attackers who have already established a foothold on a system via other means (such as initial access via phished credentials or other lower-severity exploits).

## Recommendation

Prioritize the identification and patching of all NoMachine installations within the environment. Consult the official NoMachine security advisories to determine if a specific version update addresses these local privilege escalation vulnerabilities. Conduct a review of installed software to ensure that any legacy or unmanaged NoMachine instances are identified and brought into the standard update cycle.
