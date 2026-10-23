---
brief_id: brief-2026-10-23-netdata-ndsudo-privilege-escalation
event_id: brief-2026-10-23-netdata-ndsudo-privilege-escalation
revision: 1
activity_at: "2026-10-23T18:43:16Z"
title: 'Netdata: ndsudo local privilege escalation (CVE-2024-32019)'
slug: 2026-10-netdata-ndsudo-privilege-escalation
description: Netdata’s ndsudo helper utility is vulnerable to local privilege escalation due to insecure PATH-based command resolution, allowing low-privileged users to execute arbitrary code as root.
date: "2026-10-23T18:43:16Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Needs environment validation of affected versions.
cpes:
  - cpe:2.3:a:netdata:netdata:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - local-exploitation
  - linux
vendors:
  - Netdata
products:
  - Netdata (>= 1.44.0-60, < 1.45.0-169 and >= 1.45.0, < 1.45.3)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Local privilege escalation to root in Netdata ndsudo via PATH-based command resolution.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1548.001
    technique_name: Setuid and Setgid
    evidence: Netdata’s ndsudo helper (installed setuid root) restricts which commands it will run, but resolves those commands using the caller’s PATH.
    confidence_band: high
cves:
  - id: CVE-2024-32019
    cvss: 8.8
    epss: 0.01165
    kev_status: "false"
references:
  - https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AYUB0X7-CVE-2024-32019-POC
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-AYUB0X7-CVE-2024-32019-POC&utm_source=rss&utm_medium=rss
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Upgrade Netdata to 1.45.3 or 1.45.0-169 on all Linux assets.
      owner: IT Operations
      due: 48h
      evidence: Official fix provided in vendor advisory.
  hunt_leads:
    - lead: Identify SUID binaries in non-standard paths or monitor for unusual execution of ndsudo with atypical environment variables.
      technique_id: T1548.001
      data_needed:
        - Process creation logs with environment variables.
        - Auditd logs for execve syscalls.
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Exploitation requires the attacker to modify the PATH and execute ndsudo.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Netdata to version 1.45.3.
      owner: IT Operations
      addresses: CVE-2024-32019
      evidence: Netdata Advisory (GHSA-pmhq-4cxq-wj93)
---

Netdata’s `ndsudo` helper, which is installed with the SUID bit set, is vulnerable to local privilege escalation (CVE-2024-32019). The utility whitelists specific subcommands for execution but fails to use absolute paths when calling these commands, instead resolving them via the user-controlled `PATH` environment variable. An attacker can place a malicious binary with a whitelisted name (e.g., `nvme`) into a directory under their control, prepend that directory to the `PATH` variable, and invoke `ndsudo` to execute the malicious binary with root privileges.

## Attack Chain
1. Actor identifies a system running an affected version of Netdata with `ndsudo` installed as SUID-root.
2. Actor identifies a command whitelisted by `ndsudo` that is not invoked via an absolute path (e.g., `nvme`).
3. Actor creates a malicious binary and names it to match the targeted whitelisted command.
4. Actor creates a writable directory (e.g., `/tmp/fakebin`) and places the malicious binary inside.
5. Actor sets execution permissions on the malicious binary.
6. Actor modifies the `PATH` environment variable to include the malicious directory at the beginning of the search path.
7. Actor executes `ndsudo` with the target whitelisted subcommand, causing the utility to resolve and execute the malicious binary with root privileges.

## Impact
Successful exploitation grants a local, low-privileged user (typically members of the `netdata` group) full root access to the affected system.

## Recommendation
- Upgrade Netdata to version 1.45.3 (stable) or 1.45.0-169 (nightly) to address the insecure PATH resolution.
- Audit systems for the presence of the `ndsudo` binary and ensure appropriate access controls are in place.
- If immediate patching is not possible, ensure that users do not have access to execute `ndsudo` unless strictly required.
