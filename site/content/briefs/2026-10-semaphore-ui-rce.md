---
title: Remote Code Execution in Semaphore UI via Ansible Environment Injection
slug: 2026-10-semaphore-ui-rce
description: Authenticated users with the task_runner role in Semaphore UI versions up to 2.19.16 can achieve remote code execution by injecting malicious Ansible configuration parameters into task environment payloads.
date: "2026-10-19T18:08:37Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:semaphoreui:semaphore:*:*:*:*:*:*:*:*
tags:
  - remote-code-execution
  - vulnerability
  - webserver
products:
  - Semaphore UI (<= 2.19.16)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attackers can POST tasks setting ansible_ssh_common_args with a ProxyCommand or ansible_connection=local to execute commands as the Semaphore server user.
    confidence_band: high
cves:
  - id: CVE-2026-112305
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-112305
rules:
  - title: Detect CVE-2026-112305 Exploitation - Malicious Ansible Environment Payload
    description: Detects exploitation of CVE-2026-112305 by monitoring web logs for POST requests to task endpoints containing suspicious Ansible variable injections.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.003
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Identify users with task_runner role
      owner: SOC
      due: 24h
      evidence: Vulnerability impacts task_runner role
  mitigation_plan:
    - priority: immediate
      action: Upgrade Semaphore UI to patched version
      owner: IT Operations
      addresses: CVE-2026-112305
      evidence: NVD advisory
---

Semaphore UI, a tool for managing Ansible tasks, contains a critical vulnerability (CVE-2026-112305) in versions up to 2.19.16 that enables Remote Code Execution (RCE). The vulnerability exists because the application does not properly restrict the modification of protected Ansible variables by users holding the 'task_runner' role. 

An attacker with authenticated access and the 'task_runner' role can send a crafted POST request containing a task environment JSON payload. By including keys such as 'ansible_ssh_common_args' with a malicious 'ProxyCommand' or by setting 'ansible_connection=local', the attacker can force the execution of arbitrary commands on the host system. The commands run with the privileges of the service user account executing the Semaphore UI process. Successful exploitation allows for full compromise of the application host, including the theft of stored credentials, SSH private keys, and encryption secrets.

## Attack Chain

1. Attacker authenticates to the Semaphore UI platform as a user with the 'task_runner' role.
2. Attacker initiates a new task via the web interface or API.
3. Attacker crafts a task environment JSON object containing malicious Ansible configuration overrides.
4. Attacker sends a POST request to the Semaphore task creation endpoint with the malicious JSON payload.
5. The Semaphore server processes the environment variables and passes the malicious 'ansible_ssh_common_args' or 'ansible_connection' to the Ansible runtime.
6. The Ansible process executes the injected command (e.g., via 'ProxyCommand') on the underlying host.
7. Attacker gains arbitrary command execution under the context of the Semaphore service user.
8. Attacker exfiltrates stored SSH keys, environment secrets, and encryption keys from the server.

## Impact

The vulnerability results in full remote code execution on the Semaphore UI server. Because Semaphore UI stores sensitive deployment data, this impact specifically includes the unauthorized access to and exfiltration of infrastructure encryption keys, SSH private keys for target servers, and potentially other stored application secrets. This poses a significant risk of lateral movement and full takeover of the managed infrastructure environment.

## Recommendation

1. Upgrade to the latest version of Semaphore UI immediately to patch CVE-2026-112305.
2. Review system audit logs for anomalous tasks initiated by users with the 'task_runner' role that include 'ansible_ssh_common_args' or 'ansible_connection' in the environment JSON.
3. Audit the permissions of all accounts currently assigned the 'task_runner' role and revoke access for any user not strictly requiring task execution capabilities.
4. Rotate any SSH keys, credentials, or secrets stored within the affected Semaphore UI instance following remediation.
