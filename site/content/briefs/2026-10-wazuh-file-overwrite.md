---
title: Arbitrary File Overwrite Vulnerability in Wazuh MasterHandler
slug: 2026-10-wazuh-file-overwrite
description: Wazuh versions 3.9.0 through 4.14.7 are vulnerable to an arbitrary file overwrite attack in MasterHandler that allows cluster workers to gain root remote code execution by modifying critical configuration files.
date: "2026-10-13T14:36:29Z"
lastmod: "2026-10-13T14:39:50Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*
tags:
  - privilege-escalation
  - configuration-bypass
  - cve-2026-74041
  - web-vulnerability
  - path-traversal
  - wazuh
  - vulnerability
  - authentication-bypass
  - cve-2026-74035
  - remote-code-execution
  - security-configuration-assessment
vendors:
  - Wazuh
products:
  - Wazuh (3.9.0 <= v < 4.14.8)
  - Wazuh (< 4.14.8)
  - Wazuh (4.1.1 - 4.14.7)
  - Wazuh (4.1.0-4.14.7)
  - Wazuh (4.6.0 - 4.14.7)
  - Wazuh (>= 4.3.0, < 4.14.8)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Attackers controlling a worker can use a trailing-slash basename bypass and missing extra_valid enforcement to overwrite ossec.conf and agent.conf, achieving root remote code execution.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1548
    technique_name: Abuse Elevation Control Mechanism
    evidence: Attackers... can overwrite ossec.conf and agent.conf, achieving root remote code execution across the manager and every agent.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers holding the cluster key can send DistributedAPI requests with ../ sequences in filename, bypassing REST controller validation
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: An attacker ... can perform unauthorized file writes ... ultimately executing code
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1550
    technique_name: Use Alternate Authentication Material
    evidence: A delegated user administrator can send an empty password to the user update endpoint, bypassing the reserved user guard to take over the wazuh superuser account.
    confidence_band: high
cves:
  - id: CVE-2026-74040
    cvss: 9.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74040
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74041
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74043
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74034
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74035
  - https://nvd.nist.gov/vuln/detail/CVE-2026-74036
action_plan:
  priority: immediate_escalation
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Upgrade all Wazuh manager and worker installations to 4.14.8
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-74040 requires update to v4.14.8
  hunt_leads:
    - lead: Monitor file access logs for modifications to ossec.conf or agent.conf by processes associated with cluster synchronization
      technique_id: T1548
      data_needed:
        - File integrity logs
        - Process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Arbitrary file overwrite vulnerability in MasterHandler
  mitigation_plan:
    - priority: immediate
      action: Patch Wazuh to version 4.14.8
      owner: IT Operations
      addresses: CVE-2026-74040
      evidence: NVD vulnerability disclosure
updates:
  - at: "2026-10-13T14:36:38Z"
    level: L2
    summary: added coverage for Wazuh (< 4.14.8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74041
  - at: "2026-10-13T14:36:45Z"
    level: L2
    summary: added coverage for Wazuh (4.1.1 - 4.14.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74043
  - at: "2026-10-13T14:39:37Z"
    level: L2
    summary: added coverage for Wazuh (4.1.0-4.14.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74034
  - at: "2026-10-13T14:39:43Z"
    level: L2
    summary: added coverage for Wazuh (4.6.0 - 4.14.7)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74035
  - at: "2026-10-13T14:39:50Z"
    level: L2
    summary: added coverage for Wazuh (>= 4.3.0, < 4.14.8)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-74036
---

Wazuh versions 3.9.0 through 4.14.7 contain a critical arbitrary file overwrite vulnerability located within the MasterHandler.process_files_from_worker component. The flaw arises from a basename path traversal bypass combined with a lack of input validation regarding file path enforcement. This vulnerability enables an attacker who has compromised a cluster worker node to manipulate the file synchronization process to overwrite sensitive files on the master node, specifically ossec.conf and agent.conf. By modifying these configuration files, an attacker can inject arbitrary commands, facilitating remote code execution with root privileges on the master node, which subsequently propagates to all connected agents. This vulnerability presents a high risk to security operations as it subverts the integrity of the centralized security management architecture.

## Attack Chain

1. Attacker compromises a cluster worker node through unrelated vectors.
2. Attacker initiates a malicious synchronization request to the master node's MasterHandler.process_files_from_worker.
3. Attacker crafts a path traversal payload leveraging the trailing-slash basename bypass.
4. MasterHandler processes the malicious path, failing to validate the destination against restricted directories.
5. The system overwrites the target file, such as /var/ossec/etc/ossec.conf, with attacker-controlled content.
6. The attacker injects malicious commands or configurations into the overwritten file.
7. The master node restarts or reloads the configuration, executing the injected commands as root.
8. Malicious configurations are synchronized to all connected agents, escalating impact across the enterprise footprint.

## Impact

Successful exploitation allows for full control over the Wazuh manager and its downstream agents. As the manager typically runs with root-level privileges, this permits the execution of arbitrary commands across the entire security infrastructure. This results in the potential for complete data exfiltration, disabling of security monitoring, and lateral movement throughout the environment where the Wazuh management plane is deployed.

## Recommendation

- Upgrade all Wazuh manager and cluster worker installations to version 4.14.8 or later immediately to resolve the vulnerability in MasterHandler.
- Implement strict network segmentation between cluster workers and the master node to ensure only authorized nodes can communicate with the MasterHandler component.
- Review and monitor file integrity of critical configuration files, specifically /var/ossec/etc/ossec.conf and /var/ossec/etc/shared/agent.conf, for unexpected modifications.
- Audit logs for the cluster communication service to identify anomalous synchronization requests from worker nodes.
