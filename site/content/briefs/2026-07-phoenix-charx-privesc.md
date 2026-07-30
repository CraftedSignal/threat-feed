---
title: Privilege Escalation Vulnerability in Phoenix Contact CHARX Controllers
slug: 2026-07-phoenix-charx-privesc
description: A local OS command injection vulnerability (CVE-2026-44095) in Phoenix Contact CHARX charging controllers allows low-privileged users to execute arbitrary commands as root.
date: "2026-07-30T08:13:36Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - privilege-escalation
  - industrial-control-systems
vendors:
  - Phoenix Contact
products:
  - CHARX SEC-3000
  - CHARX SEC-3050
  - CHARX SEC-3100
  - CHARX SEC-3150
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: A privilege escalation vulnerability in a script used for network configuration allows a low-privileged local user to execute arbitrary commands as root.
    confidence_band: high
cves:
  - id: CVE-2026-44095
    cvss: 7.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-44095
  - https://www.certvde.com/en/advisories/VDE-2026-008/
---

Phoenix Contact has disclosed a critical security vulnerability, tracked as CVE-2026-44095, affecting its CHARX SEC series of charging controllers. The vulnerability stems from improper neutralization of special elements used in OS commands (CWE-78) within a script responsible for network configuration. A low-privileged local user can leverage this flaw to escape restricted execution environments and inject arbitrary commands that execute with root-level privileges. This vulnerability affects CHARX SEC-3000, 3050, 3100, and 3150 models running firmware versions earlier than 1.9.1. Successful exploitation results in complete system compromise, enabling attackers to gain full control over the charging controller hardware, potentially impacting industrial control and power management functions.

## Attack Chain

1. Attacker gains low-privileged local access to the CHARX SEC charging controller via a standard user account or compromised management interface.
2. Attacker identifies the specific network configuration script that processes user-supplied input without proper validation.
3. Attacker crafts a malicious command string containing shell metacharacters designed to break out of the intended script parameters.
4. Attacker executes the malicious string via the vulnerable script interface.
5. The script fails to sanitize the input, passing the concatenated command to the underlying system shell.
6. The shell executes the injected payload with root privileges (UID 0), granting the attacker full administrative access to the device.
7. Attacker establishes persistence or performs unauthorized actions such as disabling security controls, modifying device traffic, or exfiltrating sensitive operational data.

## Impact

Successful exploitation of CVE-2026-44095 grants an attacker root access to the affected CHARX charging controllers. This enables full control over the device, which may lead to service disruption, manipulation of charging parameters, or unauthorized access to the broader industrial network environment. Organizations using these devices in critical infrastructure or public EV charging deployments are at risk of localized physical and digital impact if the controllers are compromised at scale.

## Recommendation

- Upgrade all affected Phoenix Contact CHARX SEC-3000, 3050, 3100, and 3150 controllers to firmware version 1.9.1 or higher to remediate CVE-2026-44095.
- Restrict physical and logical access to the management console of the charging controllers to prevent unauthorized local user sessions.
- Monitor local system logs on charging controllers for unexpected process execution by non-administrative user accounts.
- Audit custom scripts or configuration files on the device for improper handling of shell input parameters.
