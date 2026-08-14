---
title: Deserialization Vulnerability in alldatacenter alldata
slug: 2026-08-alldata-deserialization
description: A critical deserialization vulnerability (CVE-2026-19826) in alldatacenter alldata versions up to 0.6.8 allows remote attackers to trigger insecure deserialization via the xxl-rpc Listener component.
date: "2026-08-14T14:13:37Z"
type: advisory
types:
  - advisory
severities:
  - high
vendors:
  - alldatacenter
products:
  - alldata
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The attack may be performed from remote.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The manipulation results in deserialization.
    confidence_band: high
cves:
  - id: CVE-2026-19826
    cvss: 7.3
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Inventory instances of alldata 0.6.8 or lower.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability affects alldata up to 0.6.8.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to xxl-rpc Listener ports.
      owner: IT Operations
      addresses: CVE-2026-19826
      evidence: Remote attack vector identified.
---

A deserialization vulnerability exists in the xxl-rpc Listener component of alldatacenter alldata, affecting all versions up to 0.6.8. The flaw is located within the Hessian2Input.readObject function in the /serialize/impl/HessianSerializer.java file. An unauthenticated, remote attacker can exploit this vulnerability by sending specially crafted serialized objects to the vulnerable service. Successful exploitation leads to the deserialization of untrusted data, which can facilitate unauthorized code execution or impact the availability of the application. The project maintainers have classified the issue as "not planned," and no patch is currently available. This vulnerability is subject to public exploitation, making it a priority for organizations utilizing this software.

## Attack Chain

1. The attacker identifies an internet-facing endpoint running a vulnerable version of alldata (<= 0.6.8).
2. The attacker discovers the application utilizes the xxl-rpc Listener component for remote procedure calls.
3. The attacker crafts a malicious serialized object specifically designed to trigger the vulnerable Hessian2Input.readObject function.
4. The attacker sends the malicious payload via a network request to the targeted xxl-rpc listener port.
5. The application accepts the payload and passes the data to the HessianSerializer.java implementation.
6. The Hessian2Input.readObject function performs insecure deserialization of the provided object.
7. The deserialization process executes attacker-supplied code or triggers secondary side effects within the application runtime.
8. The attacker achieves remote code execution or application disruption within the context of the service account.

## Impact

Successful exploitation of CVE-2026-19826 allows remote, unauthenticated attackers to execute arbitrary code or cause a denial of service within the application environment. Given the nature of deserialization flaws, this may lead to full system compromise depending on the privileges of the alldata service process. Organizations currently using versions 0.6.8 or earlier are at risk, and the lack of a vendor-provided patch increases the persistence of this exposure.

## Recommendation

* Conduct an immediate audit of network assets to identify instances of alldatacenter alldata running versions 0.6.8 or earlier.
* Implement strict network segmentation to ensure the xxl-rpc Listener is not reachable from untrusted networks or the public internet.
* Monitor network traffic for anomalous inbound payloads targeting RPC endpoints associated with alldata.
* Given the maintainer's status of "not planned," evaluate the business risk of continuing to use the software or deploy virtual patching via WAF/IPS if RPC traffic patterns can be effectively characterized.
