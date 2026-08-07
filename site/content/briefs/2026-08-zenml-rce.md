---
title: Remote Code Execution in ZenML CloudpickleMaterializer
slug: 2026-08-zenml-rce
description: ZenML 0.94.6 contains a remote code execution vulnerability in the CloudpickleMaterializer component that allows arbitrary command execution via malicious pickle file injection.
date: "2026-08-07T17:34:43Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - remote-code-execution
  - deserialization
  - zenml
vendors:
  - ZenML
products:
  - ZenML (0.94.6)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The vulnerability allows attackers to execute arbitrary system commands by planting a malicious pickle file.
    confidence_band: high
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-68772
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade ZenML to patched version
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-68772 identified as RCE
  mitigation_plan:
    - priority: immediate
      action: Tighten IAM/ACLs on artifact storage
      owner: IT Operations
      addresses: Unauthorized write access to shared artifact storage
      evidence: Vulnerability requires attacker write access
---

ZenML version 0.94.6 contains a remote code execution vulnerability (CVE-2026-68772) within the CloudpickleMaterializer component. This vulnerability stems from the use of unsanitized `cloudpickle.load()` calls when materializing artifacts from the artifact store. An attacker who gains write access to the shared artifact store can replace a legitimate `artifact.pkl` file with a crafted payload containing a malicious `__reduce__` method. When a legitimate pipeline or user subsequently materializes this artifact, the Python environment automatically executes the embedded malicious commands. This vulnerability is critical for organizations using shared artifact storage in multi-user environments where local write access or compromised service accounts could allow for persistence or lateral movement within the data pipeline ecosystem.

## Attack Chain

1. Attacker gains write access to a shared artifact storage location used by ZenML.
2. Attacker locates a target `artifact.pkl` file used by an active or future pipeline.
3. Attacker generates a malicious pickle payload using `cloudpickle` that defines a `__reduce__` method to execute system commands.
4. Attacker overwrites the legitimate `artifact.pkl` file with the malicious payload.
5. A victim user or automated pipeline execution agent triggers the `CloudpickleMaterializer` to process the artifact.
6. The `CloudpickleMaterializer` executes `cloudpickle.load()` on the malicious file.
7. The embedded commands in the `__reduce__` method are executed in the security context of the pipeline process.
8. Attacker gains arbitrary code execution, potentially resulting in exfiltration or further compromise of the compute environment.

## Impact

Successful exploitation allows for remote code execution within the context of the pipeline process. This can lead to full system compromise, data exfiltration from the artifact store, or unauthorized access to credentials and sensitive data processed by the data pipelines.

## Recommendation

1. Upgrade ZenML to a patched version immediately to resolve the unsafe deserialization vulnerability in the CloudpickleMaterializer.
2. Restrict write access to shared artifact storage locations to only authorized service accounts or users.
3. Monitor file integrity for `artifact.pkl` files within the ZenML artifact store for unauthorized modifications.
4. Implement strict access control lists (ACLs) on cloud-based artifact storage (e.g., S3, GCS) to ensure only authorized CI/CD pipelines can modify stored objects.
