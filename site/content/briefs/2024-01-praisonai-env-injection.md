---
title: PraisonAI Cloud Run Environment Variable Injection Vulnerability (CVE-2026-40113)
slug: 2024-01-praisonai-env-injection
description: PraisonAI versions before 4.5.128 are vulnerable to arbitrary environment variable injection in Google Cloud Run deployments due to insufficient input validation when constructing the `--set-env-vars` argument, potentially leading to privilege escalation.
date: "2024-01-02T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - cve-2026-40113
  - cloud
  - environment variable injection
  - privilege escalation
vendors:
  - PraisonAI
products:
  - PraisonAI
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
cves:
  - id: CVE-2026-40113
    cvss: 8.4
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-40113
rules:
  - title: Detect Suspicious Google Cloud Run Environment Variable Injection
    description: Detects attempts to inject arbitrary environment variables into Google Cloud Run deployments by monitoring suspicious activity related to environment variable settings in cloud audit logs.
    platform: sigma
    severity: high
    tactics:
      - privilege_escalation
    techniques:
      - T1068
    data_sources:
      - cloudtrail
      - google_cloud_platform
      - cloudtrail
  - title: Detect PraisonAI deploy.py execution
    description: Detects execution of deploy.py which is used to deploy PraisonAI, which may indicate deployment activity and potential exploitation attempts.
    platform: sigma
    severity: low
    tactics:
      - initial_access
    techniques:
      - T1189
    data_sources:
      - process_creation
      - linux
rules_count: 2
---

PraisonAI, a multi-agent teams system, contains a vulnerability in versions prior to 4.5.128 that allows for arbitrary environment variable injection into Google Cloud Run deployments. The vulnerability, identified as CVE-2026-40113, stems from the `deploy.py` script's construction of the `--set-env-vars` argument for the `gcloud run deploy` command. Specifically, the script directly interpolates the `openai_model`, `openai_key`, and `openai_base` variables into a comma-delimited string without validating for the presence of commas within these values. Since `gcloud` uses commas as key-value pair separators, a comma within any of these values allows an attacker to inject arbitrary environment variables into the deployed Cloud Run service, leading to potential privilege escalation. This vulnerability poses a significant risk to organizations using vulnerable versions of PraisonAI, allowing attackers to potentially modify application behavior or gain unauthorized access to sensitive resources.

## Attack Chain

1. The attacker identifies a PraisonAI instance running a version prior to 4.5.128.
2. The attacker crafts a malicious payload containing a comma within the `openai_model`, `openai_key`, or `openai_base` parameters. For example, setting `openai_model` to `model,MALICIOUS_VAR=evil`
3. The attacker triggers the `deploy.py` script, passing the crafted payload to the `gcloud run deploy --set-env-vars` command.
4. `gcloud` interprets the comma in the injected value as a separator, parsing the trailing text as additional key-value pairs.
5. Arbitrary environment variables, as specified in the malicious payload, are injected into the Cloud Run service during deployment.
6. The Cloud Run service is deployed with the injected environment variables.
7. The attacker leverages the injected environment variables to escalate privileges within the application or gain unauthorized access to resources.

## Impact

Successful exploitation of CVE-2026-40113 allows attackers to inject arbitrary environment variables into a deployed Cloud Run service running PraisonAI. This can lead to privilege escalation, unauthorized access to sensitive data, and modification of application behavior. While the exact number of vulnerable PraisonAI instances is unknown, the potential impact includes compromised cloud infrastructure and data breaches, especially for organizations that rely on PraisonAI for critical business functions.

## Recommendation

*   Upgrade PraisonAI to version 4.5.128 or later to remediate CVE-2026-40113.
*   Implement input validation on `openai_model`, `openai_key`, and `openai_base` parameters within the `deploy.py` script or similar deployment scripts to prevent comma injection, mitigating the vulnerability even in older versions.
*   Monitor Google Cloud Run deployments for unexpected environment variables using cloud audit logs (service: "cloudtrail") and implement the Sigma rule `Detect Suspicious Google Cloud Run Environment Variable Injection`.
*   Review existing Cloud Run deployments for potentially malicious environment variables and revert to a clean state.
