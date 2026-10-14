---
title: Unauthenticated Remote Code Execution in MyReport Updater via gRPC
slug: 2026-10-report-one-myreport-updater-grpc-rce
description: Report One MyReport Updater versions 2.1.1 and earlier contain an unauthenticated gRPC service vulnerability allowing remote attackers to hijack the update process and achieve SYSTEM-level code execution.
date: "2026-10-14T16:37:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:reportone:myreport_updater:*:*:*:*:*:*:*:*
vendors:
  - Report One
products:
  - MyReport Updater (<= 2.1.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Report One MyReport Updater through 2.1.1 exposes an unauthenticated gRPC service on TCP port 9095.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Attackers can point the updater to a malicious reference server serving modified module archives with matching MD5 digests to write files and execute code as SYSTEM.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1574
    technique_name: Hijack Execution Flow
    evidence: The updater allows remote attackers to redirect the SYSTEM updater... to write files and execute code as SYSTEM.
    confidence_band: high
cves:
  - id: CVE-2026-110632
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110632
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Restrict inbound TCP port 9095 to trusted management subnets only
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated gRPC service on TCP port 9095
  mitigation_plan:
    - priority: immediate
      action: Upgrade MyReport Updater to current secure version
      owner: IT Operations
      addresses: CVE-2026-110632
      evidence: NVD vulnerability disclosure
---

Report One MyReport Updater, in versions 2.1.1 and earlier, exposes an unauthenticated gRPC service listening on TCP port 9095. This service provides methods that can be accessed by any network-adjacent attacker without authentication. Specifically, the UpdateConfigReferent method is vulnerable to manipulation, allowing an attacker to force the updater to pull update module archives from an attacker-controlled remote server. Because the application fails to adequately validate the authenticity of the update source, the updater will accept malicious module archives as long as the attacker provides matching MD5 digests. This flaw allows for arbitrary file writes, resulting in code execution with SYSTEM privileges on the affected host. Given the elevated permissions of the updater service, this vulnerability poses a critical risk to systems running MyReport Updater.

## Impact

The vulnerability allows unauthenticated remote attackers to gain full control over the affected system. Since the updater runs with SYSTEM privileges, the impact includes complete compromise of the host, potential lateral movement within the network, and the deployment of persistent malicious modules. This affects all organizations utilizing MyReport Updater versions 2.1.1 or earlier.

## Recommendation

1. Patch immediately: Upgrade all instances of MyReport Updater to a version beyond 2.1.1 as soon as the vendor provides a security update.
2. Network isolation: Restrict inbound access to TCP port 9095 to authorized management subnets only; the service should not be exposed to untrusted networks.
3. Monitoring: Monitor for unexpected network connections originating from the host running the MyReport Updater service, especially outbound connections to unknown or non-official update servers.
