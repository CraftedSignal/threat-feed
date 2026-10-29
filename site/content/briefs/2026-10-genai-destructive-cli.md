---
brief_id: brief-2026-10-29-genai-destructive-cli
event_id: brief-2026-10-29-genai-destructive-cli
revision: 1
activity_at: "2026-10-29T21:06:46Z"
title: 'Amazon Q Developer: Destructive Cloud CLI command execution via GenAI agent'
slug: 2026-10-genai-destructive-cli
description: Generative AI coding agents can be manipulated via prompt injection to execute unauthorized, destructive infrastructure commands using the developer's pre-existing cloud credentials.
date: "2026-10-29T21:06:46Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Verified against Elastic detection rule source.
tags:
  - cloud-security
  - genai
  - infrastructure-as-code
  - destructive
vendors:
  - Amazon
products:
  - Amazon Q Developer (v1.84.0)
affected_os:
  - Linux
  - macOS
  - Windows
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: Identifies a cloud CLI command that destroys infrastructure or identities, such as terminating EC2 instances, removing S3 buckets, or deleting IAM users, when it is spawned by a GenAI coding agent.
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: Identifies a cloud CLI command that destroys... identities, such as... deleting IAM users.
    confidence_band: high
  - tactic_id: TA0005
    tactic_name: Defense Evasion
    technique_id: T1562.008
    technique_name: Disable or Modify Cloud Logs
    evidence: Detects destructive commands including cloudtrail stop-logging.
    confidence_band: high
references:
  - https://aws.amazon.com/security/security-bulletins/AWS-2025-015/
  - https://github.com/aws/aws-toolkit-vscode/security/advisories/GHSA-7g7f-ff96-5gcw
  - https://www.theregister.com/2025/07/24/amazon_q_ai_prompt/
  - https://www.pointguardai.com/blog/clean-to-factory-state-the-ai-prompt-that-nearly-wiped-aws-accounts
  - https://github.com/elastic/detection-rules/blob/main/rules/cross-platform/impact_destructive_aws_cli_execution_by_genai_agent.toml
action_plan:
  priority: elevated
  owners:
    - SOC
    - Security Engineering
  immediate_actions:
    - action: Review all developer IAM roles for overly permissive policies and implement permission boundaries.
      owner: Security Engineering
      due: 72h
      evidence: Mitigate blast radius of credentials held by agents.
  hunt_leads:
    - lead: Search endpoint process logs for AWS, SAM, Terraform, or Kubectl CLI execution where the parent process is a known GenAI coding agent.
      technique_id: T1485
      data_needed:
        - Endpoint process creation logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Rule targets parent processes including qterm, claude, codex, cursor, etc.
---

Generative AI coding agents with direct or indirect shell access may be coerced into executing destructive cloud infrastructure commands. If an agent is compromised or subjected to prompt injection, it can leverage the developer's existing cloud session and permissions to terminate resources, delete buckets, or wipe identities. This threat vector was highlighted by the Amazon Q Developer (v1.84.0) incident (AWS-2025-015), where an agent was steered into executing commands that destroyed cloud environments.

## Impact

Successful exploitation allows for mass deletion of cloud infrastructure and identities. Observed impacts include terminal termination of EC2 instances, deletion of S3 buckets and objects, removal of IAM roles/users, and destruction of databases or Kubernetes clusters. This impact is possible because the agent operates within the authenticated security context of the developer.

## Recommendation

- Implement IAM permission boundaries on developer workstations to restrict the blast radius of credentials held by the agent.
- Audit environment variables and shell histories to detect unusual agent-invoked CLI command patterns.
- Correlate infrastructure teardown events in AWS CloudTrail with recent developer activity and AI agent logs to confirm authorization.
- Restrict the ability of AI coding agents to execute broad CLI commands in production or critical development environments.
