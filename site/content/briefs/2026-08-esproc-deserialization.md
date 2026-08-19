---
title: Deserialization Vulnerability in SPLWare esProc
slug: 2026-08-esproc-deserialization
description: An unauthenticated remote deserialization vulnerability (CVE-2026-75987) in SPLWare esProc allows attackers to execute arbitrary code via the SocketData.java component.
date: "2026-08-19T02:58:27Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - SPLWare
products:
  - esProc
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-75987
    cvss: 7.3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Inventory all servers running SPLWare esProc to identify versions <= 20260507
      owner: IT Operations
      due: 24h
      evidence: Affected version range provided in NVD CVE-2026-75987
  mitigation_plan:
    - priority: immediate
      action: Upgrade SPLWare esProc software
      owner: IT Operations
      addresses: CVE-2026-75987
      evidence: NVD vulnerability disclosure
---

SPLWare esProc versions up to and including 20260507 are vulnerable to a remote deserialization flaw identified as CVE-2026-75987. The vulnerability exists in the `ObjectInputStream.readUnshared` function located within `src/main/java/com/scudata/parallel/SocketData.java`. 

The flaw allows an unauthenticated remote attacker to pass untrusted serialized objects to the application, which are then improperly processed by the `readUnshared` method. Because the application fails to validate the input before deserialization, an attacker can manipulate the object stream to achieve remote code execution (RCE) on the underlying server. Given the nature of Java deserialization vulnerabilities, successful exploitation typically results in complete system compromise. Organizations running SPLWare esProc should audit their instances for this version and evaluate the necessity of exposure to the network.

## Impact

Successful exploitation of CVE-2026-75987 allows an unauthenticated remote attacker to achieve arbitrary code execution. This impacts the confidentiality, integrity, and availability of the host server. The vulnerability is present in the `SocketData.java` component, suggesting that any exposed network socket used for parallel processing or data transmission is a potential vector for attack.

## Recommendation

- Upgrade SPLWare esProc to a version later than 20260507 to remediate the vulnerability in `SocketData.java`.
- Isolate instances of esProc that are currently exposed to the internet until the patch is applied.
- Review network access control lists (ACLs) to restrict access to ports utilized by esProc parallel processing services to trusted internal sources only.
- Monitor application logs for unexpected deserialization errors or serialized object payloads that do not correspond to expected internal communication patterns.
