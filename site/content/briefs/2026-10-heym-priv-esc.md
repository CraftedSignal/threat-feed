---
title: Privilege Escalation in Heym Workflow Execution
slug: 2026-10-heym-priv-esc
description: Heym versions 0.0.55 through 0.0.120 contain a privilege escalation vulnerability allowing shared collaborators to exfiltrate workflow credentials by overwriting error handlers.
date: "2026-10-15T00:34:36Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:heym:heym:*:*:*:*:*:*:*:*
vendors:
  - Heym
products:
  - Heym (0.0.55-0.120)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: Heym from 0.0.55 before 0.0.121 contains a privilege escalation vulnerability that allows shared collaborators to overwrite a workflow's error_workflow_id.
    confidence_band: high
cves:
  - id: CVE-2026-110873
    cvss: 7.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-110873
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Operations
  immediate_actions:
    - action: Upgrade Heym to version 0.0.121
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-110873 remediation
  mitigation_plan:
    - priority: immediate
      action: Review and restrict workflow collaborator access
      owner: Security Operations
      addresses: CVE-2026-110873
      evidence: Source documentation of collaborator-based privilege escalation
---

Heym versions 0.0.55 through 0.0.120 are affected by a privilege escalation vulnerability identified as CVE-2026-110873. The flaw stems from an improper validation mechanism where the error_workflow_id field is omitted from the OWNER_ONLY_EXECUTION_FIELDS list. This oversight permits shared collaborators, who typically possess restricted access, to modify the error handling configuration of a workflow. By redirecting the error workflow to an attacker-controlled workflow containing an HTTP node, the attacker can force the parent workflow to trigger an error. Upon execution of this error, the system injects the owner's decrypted credentials into the attacker's workflow, facilitating unauthorized credential exfiltration. This vulnerability presents a high risk for organizations using Heym for automated workflows involving sensitive service credentials.

## Impact

The vulnerability allows unauthorized collaborators to escalate privileges and exfiltrate sensitive credentials associated with automated workflows. If exploited, an attacker can capture secrets stored within Heym, potentially compromising connected third-party services and downstream systems. The scope of impact is limited to environments where workflows are shared among collaborators with varying levels of trust.

## Recommendation

* Upgrade the Heym instance to version 0.0.121 or later to remediate CVE-2026-110873.
* Audit existing workflow permissions and shared collaborator access levels within the Heym platform to identify workflows currently susceptible to modification by unauthorized users.
* Rotate any credentials or API keys that have been utilized within shared workflows where collaborator access has been granted during the period of vulnerability.
