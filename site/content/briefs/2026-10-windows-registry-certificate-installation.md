---
title: Detection of Unauthorized Root CA Certificate Installation via Windows Registry
slug: 2026-10-windows-registry-certificate-installation
description: This brief outlines the detection of unauthorized root CA certificate installation in the Windows Registry, a technique used to facilitate man-in-the-middle attacks and bypass encrypted communication security.
date: "2026-10-12T18:20:21Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - windows
  - registry
  - defense-evasion
  - mitm
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1553
    technique_name: Subvert Trust Controls
    evidence: The analytic detects the installation of a root CA certificate by monitoring specific registry paths for SetValue events.
    confidence_band: high
references:
  - https://posts.specterops.io/code-signing-certificate-cloning-attacks-and-defenses-6f98657fc6ec
  - https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/T1553.004
rules:
  - title: Detect Unauthorized Root CA Certificate Installation
    description: Detects the installation of a root CA certificate by monitoring registry paths containing 'certificates' for SetValue events where the value name is 'Blob'.
    platform: sigma
    severity: medium
    tactics:
      - defense_evasion
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
    - action: Deploy registry monitoring for certificate store modifications.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides specific registry paths and values to monitor.
  hunt_leads:
    - lead: Search for recent additions to certificate registry hives.
      technique_id: T1553.004
      data_needed:
        - Sysmon Event ID 13
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: Analytic detects registry paths containing 'certificates'.
  mitigation_plan:
    - priority: medium
      action: Implement strict GPO policies for managing Trusted Root Certification Authorities.
      owner: IT Operations
      addresses: T1553.004
      evidence: Standard enterprise security practice to prevent unauthorized certificate installation.
---

Unauthorized installation of root Certificate Authority (CA) certificates within the Windows Registry is a technique frequently employed by threat actors to compromise the integrity of encrypted network traffic. By adding a malicious root certificate to the Windows trust store, attackers can effectively perform man-in-the-middle (MITM) attacks, enabling them to intercept, decrypt, or manipulate sensitive data transmitted over HTTPS or other TLS-encrypted protocols. 

Defenders should monitor registry modification events, specifically targeting paths associated with system certificates. The presence of a new "Blob" value within certificate-related registry keys is a high-fidelity indicator of a certificate store modification. While this behavior can occasionally be associated with legitimate software updates, it remains a critical monitoring point to ensure endpoint integrity and prevent persistent access to encrypted communications by unauthorized parties.

## Impact

Successful exploitation of this technique compromises the trust model of the affected endpoint. Attackers can leverage this to perform clandestine interception of encrypted sessions, inject malicious content into web traffic, or validate untrusted code as legitimate. This facilitates a wide range of follow-on attacks, including credential harvesting, session hijacking, and the delivery of secondary payloads, leading to potential data breaches and total loss of confidentiality for network communications.

## Recommendation

Detection engineering teams should implement monitoring for registry modifications that signal the installation of new CA certificates.
* Deploy the provided Sigma rule to detect registry modifications targeting certificate storage paths.
* Enable Sysmon Event ID 13 (RegistryValueset) to capture the necessary telemetry for this detection.
* Audit authorized certificate installation workflows to baseline legitimate behavior and reduce false positives.
