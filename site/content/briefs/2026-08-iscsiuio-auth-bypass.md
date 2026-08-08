---
title: Authentication Bypass in Open-iSCSI iscsiuio Control Socket
slug: 2026-08-iscsiuio-auth-bypass
description: CVE-2026-44944 describes an authentication bypass vulnerability in the Open-iSCSI iscsiuio control socket that allows local attackers to perform unauthorized actions.
date: "2026-08-08T09:32:22Z"
type: advisory
types:
  - advisory
severities:
  - medium
vendors:
  - Open-iSCSI
products:
  - iscsiuio
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation of Privilege Escalation Vulnerability
    evidence: CVE-2026-44944 identifies an authentication bypass vulnerability within the iscsiuio control-socket in Open-iSCSI, which could allow an unauthorized local user to perform unauthorized actions.
    confidence_band: high
cves:
  - id: CVE-2026-44944
    epss: 0.00093
references:
  - https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-44944
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Update Open-iSCSI iscsiuio to the patched version
      owner: IT Operations
      due: 72h
      evidence: CVE-2026-44944 mitigation requirement
---

The iscsiuio component of the Open-iSCSI project contains an authentication bypass vulnerability identified as CVE-2026-44944. The flaw exists within the implementation of the control-socket, which fails to properly authenticate requests. An unauthorized local attacker can leverage this weakness to interact directly with the control socket, potentially executing commands or modifying system state associated with iSCSI operations. This vulnerability poses a risk to systems relying on iSCSI storage, as it allows for privilege escalation or unauthorized control over storage connectivity by a local process or user. Defenders should prioritize updating Open-iSCSI packages to versions that implement proper socket-level authentication.

## Impact

Successful exploitation allows a local user to bypass security controls and perform unauthorized operations within the iscsiuio service, potentially leading to unauthorized storage access or disruption of iSCSI services.

## Recommendation

- Update the Open-iSCSI package to the latest version provided by your Linux distribution to remediate CVE-2026-44944.
- Review local system access logs to identify unauthorized attempts to communicate with the iscsiuio control socket.
- Apply the principle of least privilege to restrict access to the control socket if the application architecture permits.
