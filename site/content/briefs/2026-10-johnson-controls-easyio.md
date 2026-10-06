---
title: Hard-coded Credentials and Privilege Management Vulnerabilities in Johnson Controls EasyIO FG
slug: 2026-10-johnson-controls-easyio
description: Johnson Controls EasyIO FG firmware versions <=2.0b52 are affected by hard-coded credentials and improper privilege management vulnerabilities (CVE-2026-27872, CVE-2026-27873), potentially allowing full device compromise.
date: "2026-10-06T17:12:05Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:johnson_controls:easyio_fg_firmware:*:*:*:*:*:*:*:*
tags:
  - iot
  - ot
  - vulnerability
  - ics
vendors:
  - Johnson Controls
products:
  - EasyIO FG firmware (<=2.0b52)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: A vulnerability exists in EasyIO FG relating to an attacker gaining unauthorized access to the system through hard-coded credentials
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1110.001
    technique_name: 'Brute Force: Password Guessing'
    evidence: vulnerability exists in EasyIO FG relating to ... improper privilege management
    confidence_band: high
cves:
  - id: CVE-2026-27872
    epss: 0.00087
  - id: CVE-2026-27873
    epss: 0.00087
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-279-01
  - https://www.cve.org/CVERecord?id=CVE-2026-27872
  - https://www.cve.org/CVERecord?id=CVE-2026-27873
  - https://www.johnsoncontrols.com/trust-center/cybersecurity/security-advisories
action_plan:
  priority: elevated
  owners:
    - OT Security
    - Network Operations
  immediate_actions:
    - action: Isolate legacy EasyIO FG devices into restricted VLANs with no Internet egress.
      owner: Network Operations
      due: 48h
      evidence: 'Mitigation: Deploy devices only within isolated BAS/OT networks'
  mitigation_plan:
    - priority: immediate
      action: Decommission and replace EOL EasyIO FG devices with supported hardware like EasyIO Neo R1.
      owner: OT Security
      addresses: CVE-2026-27872, CVE-2026-27873
      evidence: Johnson Controls has determined that the EasyIO FG Series has reached End-of-Life (EOL) and End-of-Support (EOS) status.
---

Johnson Controls EasyIO FG series devices running firmware version 2.0b52 or earlier are susceptible to vulnerabilities identified as CVE-2026-27872 and CVE-2026-27873. These vulnerabilities stem from the use of hard-coded credentials (CWE-798) and improper privilege management (CWE-269), which can be leveraged by an attacker to gain unauthorized access and potentially achieve full device compromise. These devices are used globally in critical infrastructure sectors, including energy, manufacturing, and transportation. Because the EasyIO FG series has reached End-of-Life (EOL) and End-of-Support (EOS) status, Johnson Controls will not issue any firmware patches or code-level fixes. Organizations currently utilizing these devices in their OT/BAS networks must rely on strict network segmentation and compensatory controls to mitigate the risk of unauthorized access.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to bypass authentication mechanisms and elevate privileges, leading to full control over affected EasyIO FG hardware. Given the role of these devices in critical infrastructure such as energy and manufacturing, a compromise could result in operational disruptions, unauthorized manipulation of physical processes, or lateral movement into broader OT environments. Since no patches are available, the risk remains persistent for any device left connected to a network.

## Recommendation

Prioritized actions for security teams:
- Migrate all instances of the EasyIO FG series to current, supported hardware, such as the EasyIO Neo R1 Series, as the affected devices are EOL.
- Implement strict network isolation for any remaining units by placing them in isolated BAS/OT VLANs with no direct Internet connectivity.
- Configure firewalls to allow connections only from whitelisted engineering workstation IP addresses and block all remote login access from untrusted segments.
- Disable all unnecessary services on the devices, specifically Telnet or other insecure legacy management protocols.
- Monitor logs for repeated failed login attempts or unauthorized attempts to gain root-level access to the management interface.
- Refer to the manufacturer's advisory JCI-PSA-2026-12 for detailed mitigation and hardening steps.
