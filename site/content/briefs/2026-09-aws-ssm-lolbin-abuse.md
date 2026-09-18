---
title: Abuse of AWS Systems Manager for Remote LOLBin Execution
slug: 2026-09-aws-ssm-lolbin-abuse
description: Adversaries are abusing the AWS Systems Manager SendCommand API to remotely execute commands on EC2 instances by leveraging legitimate system utilities (LOLBins) to bypass CloudTrail parameter redaction.
date: "2026-09-18T19:14:20Z"
lastmod: "2026-09-18T19:30:30Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cloud
  - linux
  - aws
  - living-off-the-land
  - execution
  - command-and-control
  - defense-evasion
  - cloud-administration-command
vendors:
  - Amazon
products:
  - EC2
  - AWS Systems Manager
  - Systems Manager
affected_os:
  - Linux
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Adversaries may abuse SSM to execute malicious commands remotely without requiring SSH or RDP access, using legitimate system utilities.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562
    technique_name: Impair Defenses
    evidence: Adversaries may enable this feature to establish an out-of-band communication channel that evades network-based security monitoring, firewalls, and VPC controls.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1578
    technique_name: Modify Cloud Compute Infrastructure
    evidence: This rule detects successful EnableSerialConsoleAccess API calls, which may indicate an adversary attempting to establish an out-of-band access channel.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1651
    technique_name: Cloud Administration Command
    evidence: Detects the execution of commands or scripts on EC2 instances using AWS Systems Manager (SSM).
    confidence_band: high
references:
  - https://www.mitiga.io/blog/abusing-the-amazon-web-services-ssm-agent-as-a-remote-access-trojan
  - https://www.kali.org/tools/pacu/
  - https://www.100daysofredteam.com/p/ghost-in-the-cloud-abusing-aws-ssm
  - https://hackingthe.cloud/aws/post_exploitation/run_shell_commands_on_ec2/
  - https://gtfobins.github.io/
  - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_EnableSerialConsoleAccess.html
  - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-serial-console.html
  - https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud
  - https://docs.aws.amazon.com/systems-manager/latest/userguide/ssm-plugins.html
  - https://attack.mitre.org/techniques/T1651/
rules:
  - title: AWS EC2 Serial Console Access Enabled
    description: Detects successful EnableSerialConsoleAccess API calls, which may indicate an adversary attempting to establish an out-of-band communication channel to evade network security controls.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    techniques:
      - T1562.001
      - T1578.005
    data_sources:
      - cloud
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Cloud Security
  immediate_actions:
    - action: Review IAM policies for overly permissive ssm:SendCommand access.
      owner: Cloud Security
      due: 48h
      evidence: Source states that strict IAM policies should limit SSM permissions.
  hunt_leads:
    - lead: Search for unexpected process creation chains where the parent is an SSM-orchestrated shell script.
      technique_id: T1059
      data_needed:
        - Endpoint process creation logs
        - CloudTrail data
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Detection logic relies on correlating the SSM command ID between cloud and endpoint logs.
  mitigation_plan:
    - priority: immediate
      action: Enable multi-factor authentication (MFA) for IAM entities with SSM access.
      owner: Cloud Security
      addresses: Credential compromise risk
      evidence: Source recommends MFA to reduce risk of credential compromise.
updates:
  - at: "2026-09-18T19:27:06Z"
    level: L2
    summary: 'added detection rule: AWS EC2 Serial Console Access Enabled'
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/defense_evasion_ec2_serial_console_access_enabled.toml
  - at: "2026-09-18T19:30:30Z"
    level: L1
    summary: added coverage for EC2 +1 products
    sources:
      - elastic
    source_urls:
      - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/execution_ssm_sendcommand_by_rare_user.toml
---

Adversaries are increasingly abusing the AWS Systems Manager (SSM) SendCommand API to achieve remote code execution on EC2 instances. By invoking the AWS-RunShellScript document, attackers can execute arbitrary commands without requiring SSH or RDP access to the instance. Because AWS redacts sensitive command parameters within CloudTrail logs, traditional cloud-only monitoring often fails to capture the malicious intent behind these API calls. 

This activity allows threat actors to establish reverse shells, perform data exfiltration, or conduct lateral movement using pre-installed system utilities known as Living Off the Land Binaries (LOLBins). To effectively detect this behavior, security teams must correlate cloud-based API audit logs with endpoint process telemetry. By matching the unique SSM command ID across both data sources, defenders can uncover the actual command lines executed on the EC2 host, revealing the use of binaries such as curl, wget, socat, or python for malicious tasks.

## Attack Chain

1. The attacker gains initial access to the AWS environment, obtaining credentials with sufficient permissions for the ssm:SendCommand action.
2. The attacker uses the AWS CLI or SDK to invoke the SendCommand API targeting a specific EC2 instance ID.
3. The request specifies the AWS-RunShellScript document, providing the malicious payload intended for execution.
4. The AWS SSM agent on the target EC2 instance receives the instruction and initiates a local shell process (typically _script.sh) to execute the provided commands.
5. The SSM agent executes the specified LOLBin (e.g., `curl` for exfiltration or `python` for a reverse shell).
6. The endpoint telemetry records the process creation, linking the execution to the parent SSM shell runner process.
7. The attacker verifies successful execution by polling the command status via the SSM ListCommandInvocations API.
8. The final objective, such as data exfiltration or persistence establishment, is achieved without direct network access to the EC2 instance.

## Impact

Successful exploitation allows attackers to gain full remote control over EC2 instances, facilitating data theft, the deployment of backdoors, and deeper lateral movement within the cloud environment. This technique is particularly dangerous because it blends malicious activity with legitimate administrative traffic, complicates forensic analysis due to command redaction in cloud logs, and leverages trusted system binaries to evade signature-based detection.

## Recommendation

Prioritize the correlation of CloudTrail logs and endpoint process execution data using the SSM command ID as the primary join key.

- Implement monitoring for the ssm:SendCommand action in CloudTrail logs specifically focusing on the use of the AWS-RunShellScript document.
- Enable endpoint telemetry for process creation events on all Linux-based EC2 instances to track the execution of known LOLBins.
- Configure alerting to detect when a process creation event involving a LOLBin is spawned by an SSM-related shell process (e.g., processes running from /document/orchestration/).
- Apply the principle of least privilege to IAM policies, restricting ssm:SendCommand permissions only to authorized identities and specific required instances.
- Require MFA for all IAM users and roles that possess permissions to execute SSM commands.
- Utilize VPC security groups to restrict outbound traffic from EC2 instances to prevent unauthorized data exfiltration via binaries like curl or wget.
