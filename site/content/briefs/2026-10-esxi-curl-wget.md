---
title: Detection of Malicious File Transfers on VMware ESXi Hosts
slug: 2026-10-esxi-curl-wget
description: Attackers utilize curl or wget within the ESXi shell to download malicious payloads and scripts for hypervisor exploitation, a common precursor to ransomware deployment.
date: "2026-10-01T14:05:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - ransomware
  - vmware
  - command-and-control
  - ingress-tool-transfer
vendors:
  - VMware
products:
  - ESXi
mitre_ttps:
  - tactic_id: TA0011
    tactic_name: Command and Control
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: These tools download a file or contact a remote URL from the hypervisor.
    confidence_band: high
references:
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/vsphere/command_and_control_esxi_curl_or_wget.toml
  - https://lolesxi-project.github.io/LOLESXi/#
  - https://blogs.vmware.com/security/2022/10/esxi-targeting-ransomware-tactics-and-techniques-part-2.html
rules:
  - title: Detect ESXi Shell Curl or Wget Execution
    description: Detects the use of curl or wget within the ESXi shell, which may indicate the download of malicious payloads or scripts.
    platform: sigma
    severity: medium
    tactics:
      - command_and_control
    techniques:
      - T1105
    data_sources:
      - process_creation
      - linux
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy detection rule to identify curl or wget activity in ESXi shell logs.
      owner: Detection Engineering
      due: 48h
      evidence: Source provides KQL query for integration.
  hunt_leads:
    - lead: Search shell logs for curl or wget followed by file modification commands like chmod.
      technique_id: T1105
      data_needed:
        - ESXi shell logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Source recommends checking for chmod or execution after download.
  mitigation_plan:
    - priority: medium_term
      action: Disable shell access on ESXi hosts when not in use.
      owner: IT Operations
      addresses: T1105
      evidence: Source documentation identifies shell as the primary vector.
---

Security researchers and the Elastic team have identified the use of standard Linux command-line utilities, specifically `curl` and `wget`, as a high-risk activity when executed within the VMware ESXi hypervisor shell. These binaries are frequently abused by threat actors targeting virtualization infrastructure to download malicious payloads, custom scripts, or VIB (vSphere Installation Bundle) packages from remote Command and Control (C2) servers.

Once downloaded, these artifacts are typically staged in temporary directories such as `/tmp`. This technique is a critical component of the post-exploitation phase, often serving as the delivery mechanism for ransomware or persistent backdoors. Because ESXi is a hardened, stripped-down environment, the presence of these network-transfer tools being used in interactive shell sessions is an indicator of administrative maintenance or malicious intent. Defenders should correlate these commands with subsequent file execution, permission modifications, or unauthorized configuration changes to the datastore.

## Attack Chain

1. Attacker gains unauthorized shell access to the ESXi host, often via compromised administrative credentials.
2. Attacker enumerates the local environment to identify existing tools and file system permissions.
3. Attacker uses `curl` or `wget` to fetch a malicious binary or script from a remote URL.
4. The downloaded file is saved to a directory with write access, such as `/tmp`.
5. Attacker checks the integrity or functionality of the downloaded file using local system commands.
6. Attacker modifies file permissions (e.g., using `chmod`) to make the payload executable.
7. The payload is executed, resulting in ransomware encryption, VM state manipulation, or establishment of persistence.

## Impact

Successful exploitation of ESXi hosts enables attackers to gain control over the underlying hypervisor. This grants the ability to modify virtual machine configurations, access raw virtual disks, and deploy ransomware directly to the storage datastore. This impact results in widespread availability loss, massive data exfiltration potential, and operational disruption across entire virtualization clusters.

## Recommendation

Prioritize the monitoring of administrative shell activity on ESXi hosts to identify unauthorized network-transfer operations.

- Implement the detection logic below to alert on the execution of `curl` and `wget` within ESXi shell sessions.
- Review all shell logs for unauthorized egress or ingress traffic patterns.
- Investigate any files staged in `/tmp` that were fetched via network utilities, especially those followed by `chmod` or execution commands.
- Enforce strict access control to the ESXi shell, ensuring it is disabled unless required for active maintenance.
- Audit administrative sessions for activity following the file download, as indicated in the ESXi shell logs.
