---
title: AWS Bedrock Model Prompt or Completion Containing Credentials
slug: 2026-07-aws-bedrock-credential-exposure
description: A detection rule identifies AWS access key IDs, Amazon Bedrock API keys, PEM private-key blocks, and GitHub/GitLab tokens within Amazon Bedrock model prompts or completions, indicating a critical credential exposure event through misconfiguration, data leakage, or prompt injection that necessitates immediate secret rotation and investigation.
date: "2026-07-15T10:18:39Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - llm
  - aws
  - bedrock
  - credential-access
  - data-leakage
  - prompt-injection
vendors:
  - Amazon
  - GitHub
  - GitLab
products:
  - Amazon Bedrock
  - GitHub
  - GitLab
mitre_ttps:
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: Identifies an Amazon Bedrock model invocation whose prompt or completion contains an AWS access key identifier (AKIA long-term or ASIA temporary/STS, followed by 16 characters), an Amazon Bedrock API key (ABSK bearer token), or a PEM private-key block.
    confidence_band: high
references:
  - https://www.beyondtrust.com/blog/entry/aws-bedrock-security-guide-api-keys-detection-response
  - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws_bedrock/credential_access_aws_bedrock_credentials_in_model_prompt_or_completion.toml
rules:
  - title: AWS Bedrock Model Prompt or Completion Containing Credentials
    description: Detects AWS access key IDs, Amazon Bedrock API keys, PEM private-key blocks, GitHub, and GitLab tokens in Amazon Bedrock model prompts or completions, indicating a credential exposure event.
    platform: sigma
    severity: medium
    tactics:
      - credential_access
    techniques:
      - T1552
    data_sources:
      - cloud
      - aws
rules_count: 1
---

Elastic has released a detection rule that identifies instances of sensitive credentials appearing in Amazon Bedrock model prompts or completions. This rule targets AWS access key identifiers (AKIA for long-term, ASIA for temporary/STS), Amazon Bedrock API keys (ABSK bearer tokens), PEM private-key blocks, as well as GitHub and GitLab personal access tokens. Such occurrences signify a credential exposure event, potentially due to an application or user inadvertently sending live secrets to the model, or the model itself emitting credentials. This emission could result from training-data leakage, poisoned context, or a malicious prompt-injection attempt designed to exfiltrate data. The detection of these credentials within Bedrock invocation logs indicates that the secrets are exposed to the logging system, the model provider, and potentially prompt history, necessitating immediate rotation of the affected credentials and a thorough investigation into the root cause. This rule requires Amazon Bedrock model invocation logs with text data delivery enabled, ingested via the Elastic AWS Bedrock integration.

## Attack Chain

1. **Inadvertent Exposure (Initial Access/Execution)**: A user or misconfigured application directly includes live AWS access keys (AKIA/ASIA), Bedrock API keys (ABSK), PEM private keys, or GitHub/GitLab tokens within the prompt sent to an Amazon Bedrock model.
2. **Training Data or Context Leakage (Impact/Exfiltration)**: An Amazon Bedrock model, due to being trained on sensitive data or receiving context containing credentials, inadvertently includes these credentials in its completion (output).
3. **Prompt Injection (Defense Evasion/Exfiltration)**: An attacker crafts a malicious prompt, leveraging prompt injection techniques, to manipulate the Bedrock model into revealing sensitive information, including stored or contextually available credentials, in its completion.
4. **Credential Exposure in Logs (Collection/Exfiltration)**: Regardless of the source, the Bedrock service logs the full prompt and completion of `InvokeModel` or `Converse` calls, thereby persisting the exposed credentials in the invocation logs.
5. **Access to Exposed Credentials (Collection/Exfiltration)**: Threat actors or unauthorized insiders gain access to these Bedrock invocation logs, potentially retrieving the exposed AWS, Bedrock, GitHub, or GitLab credentials.
6. **Credential Abuse (Persistence/Privilege Escalation/Impact)**: The retrieved credentials are then used to gain unauthorized access to AWS resources, GitHub repositories, or GitLab projects, leading to further reconnaissance, data exfiltration, resource manipulation, or other malicious activities.

## Impact

The primary impact of credentials appearing in Amazon Bedrock model prompts or completions is the immediate exposure and potential compromise of sensitive authentication material. This event mandates the urgent rotation of any detected AWS access key IDs, Bedrock API keys, PEM private keys, or GitHub/GitLab tokens. Failure to rotate these credentials can lead to unauthorized access to cloud resources, source code repositories, and other critical systems linked to the exposed secrets. Attackers or malicious insiders with access to Bedrock logs could leverage these credentials for data exfiltration, privilege escalation, or establishing persistence within the compromised environment. The exposure also raises concerns about the integrity of LLM applications and data handling practices, potentially leading to reputational damage and regulatory non-compliance.

## Recommendation

* **Deploy the Sigma rule** in this brief to your SIEM and tune for your environment to detect credential exposure in Bedrock logs.
* **Enable AWS Bedrock model invocation logging** with text data delivery, and ensure these logs are ingested into your security monitoring platform to activate the detection logic.
* **Review `gen_ai.prompt` and `gen_ai.completion` fields** for any matches to confirm if the detected value is a live credential or a benign example.
* **Immediately rotate or deactivate** any live AWS, Bedrock, GitHub, or GitLab credentials identified by the detection rule and review AWS CloudTrail logs for any anomalous activity associated with the compromised credentials.
* **Identify and fix the application path or process** that placed the credential into the prompt, using `user.id` and `aws_bedrock.invocation.model_id` fields for investigation.
* **Implement input/output filtering** mechanisms, such as Bedrock guardrails with sensitive-information policies, to prevent future credential exposure through the model.
