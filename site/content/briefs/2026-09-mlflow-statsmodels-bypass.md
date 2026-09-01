---
title: MLflow Statsmodels Flavor Security Control Bypass
slug: 2026-09-mlflow-statsmodels-bypass
description: The MLflow 'statsmodels' flavor fails to implement the 'MLFLOW_ALLOW_PICKLE_DESERIALIZATION' security control, allowing unauthenticated attackers to achieve arbitrary code execution via crafted pickle model artifacts.
date: "2026-09-01T18:00:04Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:lfprojects:mlflow:*:*:*:*:*:*:*:*
vendors:
  - LF Projects
products:
  - mlflow (>= 2.1.0, < 3.15.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker who can upload a crafted model artifact to an accessible artifact store can achieve arbitrary code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The Statsmodels flavor invokes pickle.load directly, which can be crafted to execute arbitrary code.
    confidence_band: high
cves:
  - id: CVE-2024-37052
    cvss: 8.8
    epss: 0.00623
  - id: CVE-2024-37060
    cvss: 8.8
    epss: 0.00775
references:
  - https://github.com/advisories/GHSA-gqvg-gmmx-x4hm
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - Detection Engineering
    - IT Operations
  immediate_actions:
    - action: Upgrade MLflow to 3.15.0 or later.
      owner: IT Operations
      due: 24h
      evidence: Source recommended fix.
  mitigation_plan:
    - priority: immediate
      action: Enable authentication on all MLflow model registries.
      owner: IT Operations
      addresses: Unauthenticated artifact store access
      evidence: Default MLflow deployments lack authentication by default.
---

MLflow contains a security vulnerability where the `mlflow.statsmodels` flavor bypasses the `MLFLOW_ALLOW_PICKLE_DESERIALIZATION` security control. This control was originally introduced to prevent unsafe `pickle.load` execution during model loading, specifically to mitigate risks associated with CVE-2024-37052 through CVE-2024-37060. When operators set this variable to `False`, they intend to block all pickle-based deserialization. However, the `mlflow.statsmodels` implementation completely omits this security guard. An attacker who can upload or place a crafted MLmodel artifact into an accessible artifact store can trigger arbitrary code execution on any system or process that invokes `mlflow.pyfunc.load_model()` against the malicious model, regardless of the environment configuration. This vulnerability effectively nullifies a primary defense-in-depth measure against remote code execution in MLflow deployments.

## Attack Chain

1. Attacker identifies an accessible MLflow artifact store or model registry without authentication (default deployments).
2. Attacker crafts a malicious `model.pkl` payload that triggers command execution upon deserialization.
3. Attacker creates a corresponding `MLmodel` YAML file specifying `mlflow.statsmodels` as the loader module.
4. Attacker uploads the malicious `model.pkl` and `MLmodel` files to the target artifact store.
5. Attacker influences a target application or ML pipeline to call `mlflow.pyfunc.load_model()` with the path to the malicious model.
6. The `mlflow.pyfunc.load_model()` function dispatches the load request to `mlflow.statsmodels._load_pyfunc()`.
7. `mlflow.statsmodels` executes `smio.load_pickle()` without checking the `MLFLOW_ALLOW_PICKLE_DESERIALIZATION` environment variable.
8. The malicious pickle payload deserializes, resulting in arbitrary code execution with the privileges of the calling process.

## Impact

Successful exploitation allows unauthenticated attackers to execute arbitrary code with the permissions of the MLflow service or the application loading the model. This can lead to full system compromise, exfiltration of sensitive model data, or persistence within the environment. Targeted sectors include organizations leveraging MLflow for MLOps, particularly those with internet-exposed model registries lacking authentication.

## Recommendation

1. Upgrade MLflow to version 3.15.0 or later immediately to include the guard logic.
2. Implement strict authentication for all MLflow artifact stores and model registries to prevent unauthorized model uploads.
3. Audit all artifact stores for suspicious or unknown `MLmodel` files referencing the `mlflow.statsmodels` flavor.
4. If upgrading is not immediately feasible, implement strict file-system access controls (ACLs) on model storage locations to ensure only trusted service identities can modify model artifacts.
