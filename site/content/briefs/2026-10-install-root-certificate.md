---
title: Detection of Malicious Root Certificate Installation on Linux
slug: 2026-10-install-root-certificate
description: This brief covers the detection of unauthorized root certificate installation on Linux systems, a technique used by attackers to intercept encrypted traffic and disable TLS warnings.
date: "2026-10-13T13:45:10Z"
type: advisory
types:
  - advisory
severities:
  - low
tags:
  - defense-impairment
  - linux
  - tls
  - certificate-manipulation
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: Detects installation of new certificate on the system which attackers may use to avoid warnings when connecting to controlled web servers or C2s
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/linux/process_creation/proc_creation_lnx_install_root_certificate.yml
  - https://capec.mitre.org/data/definitions/479.html
rules:
  - title: Detect Installation of New Root Certificate on Linux
    description: Detects the use of standard Linux utilities to update system certificate trust stores, which may indicate the installation of a rogue root CA.
    platform: sigma
    severity: low
    tactics:
      - defense-impairment
    techniques:
      - T1553.004
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: monitor_or_close
  owners:
    - Detection Engineering
  hunt_leads:
    - lead: Identify historical execution of certificate update binaries.
      technique_id: T1553.004
      data_needed:
        - Process creation logs containing update-ca-certificates or update-ca-trust
      priority: low
      confidence: medium
      disposition: convert_to_detection
      evidence: Source document identifies these as utilities to monitor for this behavior.
---

Attackers may install unauthorized root certificates on a compromised system to intercept, inspect, or modify TLS-encrypted traffic. By adding a rogue certificate to the system's trusted store, an attacker can effectively bypass browser and application warnings when performing Man-in-the-Middle (MitM) attacks against C2 communications or sensitive user data. This technique is often associated with the delivery of adware or persistent spyware capable of monitoring encrypted sessions. Defenders should monitor for the execution of system update utilities that modify certificate trust stores, such as 'update-ca-certificates' on Debian-based systems or 'update-ca-trust' on RHEL-based systems. These actions are legitimate administrative tasks but represent a high-risk activity when performed outside of authorized configuration management or maintenance windows.

## Impact

Successful installation of an unauthorized root certificate can lead to the total compromise of confidentiality for all network traffic originating from the affected host, as the attacker can sign malicious traffic with a trusted identity. This technique has historically been utilized by adware vendors to inject content into encrypted sessions and by advanced actors to maintain persistence within an environment while evading detection by network security monitoring tools.

## Recommendation

Deploy detection rules to monitor for the execution of certificate store update utilities on critical infrastructure and workstations.

- Deploy the Sigma rule in this brief to your SIEM to alert on the modification of local certificate trust stores.
- Review logs for any unauthorized execution of 'update-ca-certificates' or 'update-ca-trust' as part of your daily threat hunting or log review procedures.
- Establish an allowlist for known administrative service accounts or configuration management tools (such as Ansible, Salt, or Puppet) that legitimately trigger these binaries.
