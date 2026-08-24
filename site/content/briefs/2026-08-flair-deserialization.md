---
title: Remote Code Execution via Insecure Deserialization in Flair
slug: 2026-08-flair-deserialization
description: Flair versions 0.15.0 and 0.15.1 contain a persistent deserialization vulnerability in the clustering module, enabling arbitrary code execution when processing untrusted model files.
date: "2026-08-24T16:02:26Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:informatik.hu-berlin:flair:0.14.0:*:*:*:*:*:*:*
vendors:
  - Flair
products:
  - Flair (0.15.0)
  - Flair (0.15.1)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Loading a model supplied by an attacker therefore runs that attacker's code with the privileges of the loading process.
    confidence_band: high
cves:
  - id: CVE-2026-76843
    cvss: 7.8
  - id: CVE-2024-10073
    cvss: 5
    epss: 0.00552
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-76843
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all applications utilizing Flair versions 0.15.0 and 0.15.1
      owner: Security Engineering
      due: 24h
      evidence: Flair versions 0.15.0 and 0.15.1 contain a deserialization vulnerability
  mitigation_plan:
    - priority: immediate
      action: Upgrade Flair to a patched version or restrict model loading functions
      owner: IT Operations
      addresses: CVE-2026-76843
      evidence: The official Flair wheels for 0.15.0 and 0.15.1 still contain flair/models/clustering.py
---

Flair versions 0.15.0 and 0.15.1 contain a critical deserialization vulnerability (CVE-2026-76843) stemming from the inclusion of the 'flair/models/clustering.py' module in distributed Python wheels. The 'ClusteringModel.load' static method improperly utilizes 'pickle.loads(joblib.load(...))' to process model files. This behavior allows an attacker to achieve arbitrary code execution by supplying a maliciously crafted model file to an application utilizing the library. This issue persists despite earlier efforts to address similar risks in CVE-2024-10073 by removing the module from the documented API; however, the code remains present in the distribution and reachable via direct import. Defenders should treat any application utilizing Flair 0.15.0 or 0.15.1 as potentially vulnerable to remote code execution if it processes user-supplied model files.

## Impact

Successful exploitation results in arbitrary code execution with the privileges of the application process. This vulnerability affects downstream systems and services that rely on the Flair library for machine learning model processing, potentially leading to full system compromise if the service runs with elevated permissions or lacks sandbox isolation.

## Recommendation

* Immediately audit environments for the presence of Flair versions 0.15.0 and 0.15.1.
* Implement strict input validation and access controls for any model files ingested by applications, as native serialization formats like pickle are inherently unsafe for untrusted data.
* Upgrade to a version of Flair where the 'flair.models.clustering' module is entirely removed from the distributed artifact.
* For legacy systems that cannot be updated, implement process-level sandboxing (such as containers with minimal privileges) to isolate the execution of model loading routines.
