---
title: Sensitive Data Exposure in OpenTofu Static Evaluation
slug: 2026-08-opentofu-sensitive-leak
description: OpenTofu versions 1.8.0 through 1.8.2 fail to correctly restrict sensitive variables during static evaluation, leading to the potential exposure of sensitive information in module and backend configurations.
date: "2026-08-16T14:25:46Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - OpenTofu
products:
  - OpenTofu (1.8.0-1.8.2)
cves:
  - id: CVE-2024-58375
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2024-58375
  - https://github.com/opentofu/opentofu/security/advisories/GHSA-wpr2-j6gr-pjw9
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - DevOps
  immediate_actions:
    - action: Upgrade OpenTofu instances to 1.8.3
      owner: DevOps
      due: 48h
      evidence: Fixed in OpenTofu 1.8.3, which adds explicit errors to prevent the use of sensitive values in these contexts.
  mitigation_plan:
    - priority: immediate
      action: Review infrastructure-as-code for sensitive variable usage
      owner: DevOps
      addresses: CVE-2024-58375
      evidence: Sensitive variables may be exposed through these configuration elements instead of producing an error.
---

OpenTofu versions 1.8.0 through 1.8.2 contain a vulnerability (CVE-2024-58375) regarding the handling of sensitive variables and local values. When users enable the static evaluation of module sources, versions, or backend configurations, the application fails to enforce the restriction of values marked as sensitive. Instead of throwing a validation error as intended, the system may leak these sensitive values through these configuration elements. This exposure could allow unauthorized access to sensitive secrets, credentials, or environment-specific data handled within infrastructure-as-code configurations. The issue is addressed in OpenTofu 1.8.3, which introduces mandatory validation errors to prevent the use of sensitive values in these contexts.

## Impact

Successful exploitation could result in the exposure of sensitive secrets (e.g., API keys, passwords, or tokens) contained in configuration files. This data could be accessed by any actor with read access to the infrastructure code, logs, or state files, potentially leading to privilege escalation or further compromise of the integrated cloud environments.

## Recommendation

* Immediately audit all OpenTofu configurations for instances where sensitive variables might be utilized in module sources, versions, or backend configurations.
* Upgrade all instances of OpenTofu to version 1.8.3 or later to benefit from the implemented validation errors and prevent accidental leakage.
* Review logs and version control history for infrastructure-as-code deployments using OpenTofu 1.8.0-1.8.2 to identify potential prior exposure of sensitive variables.
