---
title: Local Privilege Escalation in NetworkManager-l2tp via pppd Directive Injection
slug: 2026-09-networkmanager-l2tp-rce
description: An improper input validation vulnerability in NetworkManager-l2tp (CVE-2026-93337) allows local users with VPN creation permissions to inject malicious directives into the pppd configuration, leading to arbitrary code execution as root.
date: "2026-09-17T21:59:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:networkmanager-l2tp_project:networkmanager-l2tp:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - linux
  - cve
products:
  - NetworkManager-l2tp
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The improper input validation allows local users to inject arbitrary pppd directives, causing the privileged pppd process to load an attacker-controlled shared object.
    confidence_band: high
cves:
  - id: CVE-2026-93337
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-93337
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Review local user permissions for VPN configuration to minimize the attack surface for CVE-2026-93337.
      owner: IT Operations
      due: 48h
      evidence: Source notes vulnerability requires VPN connection creation permissions.
  mitigation_plan:
    - priority: immediate
      action: Monitor for patched versions of the NetworkManager-l2tp package and apply to all affected Linux systems.
      owner: IT Operations
      addresses: CVE-2026-93337
---

CVE-2026-93337 describes an improper input validation vulnerability within NetworkManager-l2tp that facilitates privilege escalation. Local users who possess the necessary permissions to create VPN connections can manipulate the 'mru' or 'mtu' properties by appending non-numeric characters to a valid integer. The application's 'write_config_option()' function improperly validates this input and writes the entire string verbatim into the 'pppd' options configuration file. 

Because the 'pppd' process runs with root privileges, this injection vector allows an attacker to insert a 'plugin' directive into the configuration file. When the 'pppd' daemon subsequently starts or reloads its configuration, it interprets this injected directive and loads an attacker-specified shared object file. This enables an unprivileged local attacker to achieve arbitrary code execution in the context of the root user, significantly impacting system integrity and confidentiality.

## Impact

Successful exploitation allows a local user with standard VPN configuration permissions to escalate privileges to root. This impacts any Linux system utilizing NetworkManager-l2tp, potentially leading to full system compromise, exfiltration of sensitive credentials, or the installation of persistent rootkits.

## Recommendation

1. Audit system configurations for users with VPN connection creation permissions and restrict access to strictly necessary accounts.
2. Monitor for unauthorized modifications to files located in /etc/ppp/options or other pppd configuration directories.
3. Update NetworkManager-l2tp to the patched version as soon as provided by the distribution vendor to mitigate the input validation flaw in 'write_config_option()'.
4. Implement endpoint monitoring to detect unusual 'pppd' process invocations, particularly those referencing non-standard shared object files or unexpected configuration paths.
