---
title: Command Injection in Lantronix Console Managers (CVE-2026-80143)
slug: 2026-09-lantronix-command-injection
description: Authenticated attackers can execute arbitrary shell commands as root on multiple Lantronix console manager models by exploiting an undocumented MFC EEPROM read command that triggers command injection via a system call.
date: "2026-09-22T16:37:22Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - cve-2026-80143
  - command-injection
  - network-infrastructure
vendors:
  - Lantronix
products:
  - SLC8000 (< 9.7.0.2)
  - EMG8500 (< 9.7.0.1)
  - EMG7500 (< 9.7.0.1)
  - SLB882 (< 9.7.0.2)
  - SLCx-03 (< 9.7.0.2)
  - SLCx-02 (< 9.7.0.2)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Authenticated attackers can execute arbitrary shell commands as root by exploiting an undocumented mfc eeprom read command that passes unsanitized user input to a system() call.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated attacker, regardless of their privilege level, can leverage this flaw to execute arbitrary commands with root privileges.
    confidence_band: high
cves:
  - id: CVE-2026-80143
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-80143
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory all Lantronix SLC8000, EMG8500, EMG7500, SLB882, SLCx-03, and SLCx-02 devices
      owner: IT Operations
      due: 24h
      evidence: Source advisory lists these models as affected by CVE-2026-80143
  mitigation_plan:
    - priority: immediate
      action: Upgrade firmware for SLC8000 to 9.7.0.2 and EMG8500/EMG7500 to 9.7.0.1
      owner: IT Operations
      addresses: CVE-2026-80143
      evidence: Source specifies these versions as the fix
---

Lantronix console managers including the SLC8000 (versions before 9.7.0.2), EMG8500 and EMG7500 (versions before 9.7.0.1), and all versions of the SLB882, SLCx-03, and SLCx-02 contain a critical command injection vulnerability (CVE-2026-80143). This vulnerability stems from an undocumented MFC EEPROM read command that fails to sanitize user-supplied input before passing it to a system call. An authenticated attacker, regardless of their privilege level, can leverage this flaw to execute arbitrary commands with root privileges. Given the nature of these devices as console managers, successful exploitation provides total control over the appliance and potentially facilitates unauthorized access to downstream serial-attached infrastructure.

## Impact

Successful exploitation results in full loss of confidentiality, integrity, and availability of the targeted console manager. Because these devices manage serial connections to other networking hardware, an attacker could pivot or conduct lateral movement into the serial-attached environment. The vulnerability impacts enterprise infrastructure management, posing a severe risk to data center availability and administrative control over managed assets.

## Recommendation

Prioritize the immediate patching of vulnerable Lantronix console managers.
* Upgrade SLC8000 devices to firmware v9.7.0.2 or later.
* Upgrade EMG8500 and EMG7500 devices to firmware v9.7.0.1 or later.
* For legacy or unsupported models (SLB882, SLCx-03, SLCx-02) where patches may not be available, restrict management interface access to highly controlled jump hosts and disable the terminal or CLI interface for non-administrative users.
