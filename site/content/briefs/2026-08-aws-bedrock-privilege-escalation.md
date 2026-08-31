---
title: AWS Bedrock AgentCore Privilege Escalation via IAM Role Assumption
slug: 2026-08-aws-bedrock-privilege-escalation
description: Attackers with iam:PassRole and Bedrock resource creation permissions can escalate privileges by creating AgentCore resources with attached high-privilege IAM roles.
date: "2026-08-31T17:53:03Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - cloud
  - aws
  - privilege-escalation
  - persistence
vendors:
  - Amazon
products:
  - AWS Bedrock
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: When an attacker with iam:PassRole permission creates an AgentCore resource and attaches a privileged role, subsequent invocations inside that resource execute as the attached role.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1098
    technique_name: Account Manipulation
    evidence: When an attacker with iam:PassRole and bedrock-agentcore:Create* permissions can attach a privileged role and then invoke the resource to operate as that role.
    confidence_band: high
rules:
  - title: Detect AWS Bedrock AgentCore Resource Creation with IAM Role
    description: Detects the creation of Bedrock AgentCore resources with an IAM role attached, which may indicate an attempt to escalate privileges via resource identity assumption.
    platform: sigma
    severity: medium
    tactics:
      - privilege_escalation
    techniques:
      - T1078.004
    data_sources:
      - process_creation
      - aws
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Enable CloudTrail data-plane logging for Bedrock AgentCore services.
      owner: SOC
      due: 24h
      evidence: The subsequent Start/Invoke data-plane events are NOT captured by the default management events trail.
  hunt_leads:
    - lead: Audit existing Bedrock resources for attached IAM roles that exceed the principle of least privilege.
      technique_id: T1078
      data_needed:
        - AWS CloudTrail history
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Examine aws.cloudtrail.request_parameters for the attached role ARN.
  mitigation_plan:
    - priority: immediate
      action: Restrict iam:PassRole permissions using IAM conditions limiting allowed target services and roles.
      owner: IT Operations
      addresses: Privilege Escalation via PassRole
      evidence: Review the IAM PassRole permission of the calling identity.
---

AWS Bedrock AgentCore services, including code interpreters, agent runtimes, browser sessions, and harnesses, execute user-defined workloads within isolated MicroVM environments. A privilege escalation vector exists where an attacker possessing both `iam:PassRole` and `bedrock-agentcore:Create*` permissions can create these resources and explicitly attach a privileged IAM execution role. Once the resource is initialized, any code or session initiated within that environment assumes the identity of the attached role. This allows attackers to bypass their original permission boundaries, effectively inheriting the permissions of roles that trust `bedrock-agentcore.amazonaws.com`. Because standard CloudTrail management events do not capture the subsequent data-plane operations (e.g., code execution or session invocation), this activity often remains invisible to organizations that have not enabled specific data-plane logging.

## Impact

Successful exploitation allows an attacker to escalate privileges to match the scope of an assigned IAM role. This can result in unauthorized access to sensitive data, modification of cloud infrastructure, or further lateral movement within an AWS environment. The technique affects organizations utilizing AWS Bedrock for AI/ML workloads where IAM roles are insufficiently scoped or where identity-based access controls are not strictly enforced on the provisioning of AgentCore resources.

## Recommendation

- Enable data-plane logging for Bedrock AgentCore to ensure that post-creation session invocations are captured in logs.
- Implement strict IAM policies for `iam:PassRole`, ensuring that callers are restricted using `iam:PassedToService` conditions specifically limiting the roles that can be passed to Bedrock.
- Audit all `CreateCodeInterpreter`, `CreateAgentRuntime`, `CreateBrowser`, and `CreateHarness` events in CloudTrail to identify provisioning by non-standard users or roles.
- Revoke `iam:PassRole` permissions from non-privileged identities and rotate credentials for any roles that may have been compromised through unauthorized resource association.
