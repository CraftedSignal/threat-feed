---
title: Multiple Vulnerabilities in MLflow Enabling Arbitrary Code Execution
slug: 2026-09-mlflow-code-execution
description: Multiple vulnerabilities in MLflow, identified as CVE-2023-6976, CVE-2023-6977, and CVE-2023-6978, allow remote attackers to execute arbitrary code due to improper input validation and insecure deserialization.
date: "2026-09-24T13:58:02Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lfai:mlflow:*:*:*:*:*:*:*:*
  - cpe:2.3:a:lfprojects:mlflow:*:*:*:*:*:*:*:*
vendors:
  - LF AI & Data Foundation
products:
  - MLflow
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The source indicates that multiple vulnerabilities in MLflow allow remote attackers to execute arbitrary code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The identified vulnerabilities involve improper input validation and insecure deserialization, leading to arbitrary code execution.
    confidence_band: high
cves:
  - id: CVE-2023-6976
    cvss: 8.8
    epss: 0.01016
  - id: CVE-2023-6977
    cvss: 7.5
    epss: 0.03924
references:
  - https://wid.cert-bund.de/portal/wid/securityadvisory?name=WID-SEC-2026-3562
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6976
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6977
  - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-6978
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Patch MLflow instances to the vendor-recommended version remediating CVE-2023-6976, CVE-2023-6977, and CVE-2023-6978
      owner: IT Operations
      due: 48h
      evidence: Source advisory confirms the presence of these vulnerabilities requiring remediation
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to MLflow instances to authorized internal segments
      owner: Network Security
      addresses: CVE-2023-6976, CVE-2023-6977, CVE-2023-6978
      evidence: RCE vulnerabilities necessitate reducing exposure to untrusted entities
---

The MLflow platform, managed by the LF AI & Data Foundation, is susceptible to multiple vulnerabilities that allow for remote code execution (RCE). These vulnerabilities, tracked under CVE-2023-6976, CVE-2023-6977, and CVE-2023-6978, arise from weaknesses in input validation and insecure deserialization processes within the software. These flaws enable an unauthenticated or low-privileged attacker to inject malicious payloads into the MLflow environment, leading to full system compromise. Given MLflow's common role in machine learning pipelines, a successful exploit could grant an attacker access to sensitive model data, training parameters, and the underlying infrastructure running the MLflow server or tracking components. Defenders should prioritize patching and assess exposure of MLflow instances to untrusted networks.

## Impact

Successful exploitation of these vulnerabilities allows an attacker to achieve arbitrary code execution on the server hosting MLflow. This level of access facilitates full environment compromise, potentially resulting in data exfiltration, tampering with machine learning model artifacts, and lateral movement within the network. These vulnerabilities represent a high risk for organizations leveraging MLflow for MLOps, particularly in cloud-native or research environments where the platform may be exposed to broader network segments.

## Recommendation

Prioritize patching all MLflow installations to the latest version where these CVEs are addressed. As immediate mitigation, ensure that MLflow tracking servers are restricted to trusted internal networks and utilize robust authentication mechanisms. Review server logs for suspicious API requests or unexpected process execution patterns originating from the MLflow service account.
