---
title: Detection of Unauthorized Root or CA Certificate Installation
slug: 2026-09-cert-store-modifications
description: Adversaries can install malicious root or CA certificates into the Windows registry to facilitate traffic interception, bypass security controls, and establish persistence.
date: "2026-09-01T12:12:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - registry
  - certificate-management
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: Adversaries can install a root certificate on a compromised system to enable them to intercept and inspect encrypted traffic.
    confidence_band: high
references:
  - https://github.com/SigmaHQ/sigma/blob/main/rules/windows/registry/registry_set/registry_set_install_root_or_ca_certificat.yml
  - https://github.com/redcanaryco/atomic-red-team/blob/f339e7da7d05f6057fdfcdd3742bfcf365fee2a9/atomics/T1553.004/T1553.004.md#atomic-test-6---add-root-certificate-to-currentuser-certificate-store
  - https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
rules:
  - title: Detect Addition of New Root or CA Certificate to Windows Registry
    description: Detects the addition of new root, CA or AuthRoot certificates to the Windows registry by monitoring modifications to Certificate Store registry keys.
    platform: sigma
    severity: medium
    tactics:
      - impact
    techniques:
      - T1553.004
    data_sources:
      - registry_set
      - windows
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy the Sigma rule to monitor for unauthorized certificate store modifications.
      owner: Detection Engineering
      due: 72h
      evidence: Source documentation for T1553.004
  hunt_leads:
    - lead: Search for existing root certificate installations that do not match the organization's approved certificate inventory.
      technique_id: T1553.004
      data_needed:
        - Registry audit logs
        - Certificate store inventory exports
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Presence of unknown root certificates is a high-fidelity indicator of potential compromise.
  mitigation_plan:
    - priority: medium
      action: Use Group Policy or MDM to enforce approved certificate stores and restrict unauthorized modifications.
      owner: IT Operations
      addresses: T1553.004
      evidence: Mitigation of subversion of trust controls
---

The installation of unauthorized root or Certification Authority (CA) certificates into the Windows registry is a technique used by adversaries to facilitate malicious activities such as man-in-the-middle (MitM) attacks, bypass certificate validation for malicious payloads, and ensure the persistence of rogue communication channels. By modifying specific registry keys within the SystemCertificates hive, an attacker can force the operating system to trust a compromised or attacker-controlled certificate. This technique is often observed during post-exploitation phases or as a means to subvert enterprise-grade security appliances that rely on SSL/TLS inspection. Defenders should prioritize visibility into registry modifications affecting the Windows certificate store to identify unauthorized trust anchors being added to the environment.

## Impact

Successful installation of unauthorized root certificates allows attackers to intercept encrypted traffic, bypass application-level certificate pinning, and establish persistent access by masquerading as trusted internal services or entities, leading to potential data exfiltration and credential theft.

## Recommendation

1. Deploy the provided Sigma rule to monitor registry modifications within the Windows Certificate Store locations.
2. Implement an allowlist for known enterprise CA certificates and alert on any additions to the Root, CA, or AuthRoot certificate stores not initiated by authorized management software.
3. Regularly audit endpoints for unexpected certificates in the registry and compare them against approved organizational certificate inventories.
