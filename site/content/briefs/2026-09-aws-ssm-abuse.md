---
title: Abuse of AWS Systems Manager Session Manager for Remote Execution
slug: 2026-09-aws-ssm-abuse
description: Adversaries abuse AWS Systems Manager (SSM) Session Manager to gain interactive shell access and perform remote command execution on EC2 instances or managed hybrid nodes.
date: "2026-09-18T19:14:31Z"
lastmod: "2026-09-18T19:37:24Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud-security
  - remote-execution
  - lateral-movement
vendors:
  - Amazon
products:
  - AWS Systems Manager
  - EC2
affected_os:
  - Windows
  - Linux
  - macOS
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries abuse it for remote execution and lateral movement using legitimate AWS credentials and IAM permissions.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
    evidence: Session Manager provides interactive shell access to EC2 instances and hybrid nodes without bastion hosts or open inbound ports.
    confidence_band: high
references:
  - https://www.mitiga.io/blog/abusing-the-amazon-web-services-ssm-agent-as-a-remote-access-trojan
  - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/discovery_ssm_inventory_reconnaissance.toml
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/lateral_movement_aws_ssm_start_session_to_ec2_instance.toml
rules:
  - title: Detect Suspicious Child Process Execution from AWS SSM Session Worker
    description: Detects potentially unauthorized process execution spawned by AWS Systems Manager (SSM) worker processes.
    platform: sigma
    severity: medium
    tactics:
      - execution
    techniques:
      - T1059
      - T1651
    data_sources:
      - process_creation
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Deploy process-creation detection rule for SSM worker activity
      owner: Detection Engineering
      due: 48h
      evidence: Source detection rule logic
  hunt_leads:
    - lead: Audit CloudTrail logs for StartSession API calls correlated with suspicious parent-child process pairs
      technique_id: T1651
      data_needed:
        - CloudTrail Management Events
        - Endpoint Process Logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Correlate timing with AWS CloudTrail for StartSession or related SSM API calls
  mitigation_plan:
    - priority: immediate
      action: Restrict ssm:StartSession IAM permissions to only authorized administrative principals
      owner: IT Operations
      addresses: Cloud Administration Command (T1651)
      evidence: Adversaries abuse it for remote execution using legitimate AWS credentials
updates:
  - at: "2026-09-18T19:37:24Z"
    level: L1
    summary: new product
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/lateral_movement_aws_ssm_start_session_to_ec2_instance.toml
---

AWS Systems Manager (SSM) Session Manager is a service designed to provide interactive shell access to EC2 instances and managed hybrid nodes without the need for bastion hosts or open inbound network ports. While this functionality is intended for legitimate administrative access, it presents a significant vector for post-exploitation activity. Adversaries with access to valid AWS credentials or those who have compromised an instance role with `ssm:StartSession` permissions can leverage the SSM agent to spawn arbitrary processes. 

The SSM agent utilizes worker processes, such as `ssm-session-worker` and `ssm-document-worker`, to handle incoming requests. When an attacker initiates a session, their commands are executed as child processes of these workers. This technique allows for stealthy remote execution, as the activity originates from a trusted system binary. Detection of this behavior is challenging due to the mix of legitimate administrative traffic and malicious commands, necessitating careful behavioral analysis and environment-specific tuning.

## Attack Chain

1. Attacker gains access to AWS credentials or compromises an IAM role with `ssm:StartSession` permissions.
2. Attacker initiates a session using the AWS CLI or SDK to connect to a target EC2 instance or managed node.
3. The SSM Agent on the target host receives the connection request and spawns a `ssm-session-worker` process.
4. The attacker sends shell commands or scripts through the established SSM tunnel.
5. The `ssm-session-worker` spawns a child process (e.g., `/bin/bash` or `powershell.exe`) to execute the attacker's instructions.
6. Attacker performs reconnaissance, credential harvesting, or further lateral movement using the elevated privileges of the agent.
7. Attacker maintains persistent access or exfiltrates data by executing additional payloads from the shell session.

## Impact

Successful abuse of SSM Session Manager allows an attacker to operate within the target environment as an authenticated administrator. This grants them the ability to bypass network-level security controls, execute arbitrary code, steal sensitive credentials stored on the instance, and move laterally across the cloud environment. The potential damage includes full system compromise, data theft, and the deployment of further malware, affecting any sector that relies on AWS EC2 or SSM for infrastructure management.

## Recommendation

Prioritize the identification of unauthorized SSM session activity by auditing CloudTrail logs for `StartSession` events. Enable process-creation logging on all managed nodes to detect anomalous child processes spawned by SSM worker binaries.

- Deploy the Sigma rule below to monitor process lineages originating from SSM session workers.
- Review CloudTrail logs to map `ssm-session-worker` process timestamps to specific IAM principals or AWS access keys.
- Establish an exclusion list for known automation service accounts and standard administrative scripts to reduce false positives in the detection rule.
- Enforce the Principle of Least Privilege for IAM roles assigned to EC2 instances, ensuring only authorized users have access to SSM Session Manager.
