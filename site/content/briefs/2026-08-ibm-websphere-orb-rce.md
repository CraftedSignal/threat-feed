---
title: IBM WebSphere Application Server ORB Unsafe Reflection Vulnerability
slug: 2026-08-ibm-websphere-orb-rce
description: A vulnerability in the Object Request Broker (ORB) component of IBM SDK for Java allows an unauthenticated attacker to trigger remote code execution via arbitrary class instantiation.
date: "2026-08-05T17:20:37Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - vulnerability
  - remote-code-execution
  - java
vendors:
  - IBM
products:
  - WebSphere Application Server (8.5)
  - WebSphere Application Server (9.0)
  - WebSphere Application Server - Liberty (Continuous delivery)
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The flaw in the ORB component may allow a malicious IIOP server to induce loading and instantiation of arbitrary classes.
    confidence_band: high
cves:
  - id: CVE-2026-8400
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8400
  - https://www.ibm.com/support/pages/node/7282446
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch IBM WebSphere Application Server per IBM bulletin node 7282446
      owner: IT Operations
      due: 72h
      evidence: IBM Corporation advisory node 7282446
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to IIOP ports to known-good management IP ranges
      owner: Network Security
      addresses: CVE-2026-8400
      evidence: Vulnerability requires IIOP server interaction
---

IBM WebSphere Application Server versions 8.5, 9.0, and the Liberty Continuous Delivery release contain a critical vulnerability in the Object Request Broker (ORB) component of the integrated IBM SDK, Java Technology Edition. Tracked as CVE-2026-8400, the flaw is classified under CWE-470 (Use of Externally-Controlled Input to Select Classes or Code). This vulnerability stems from unsafe reflection practices within the ORB's handling of IIOP (Internet Inter-ORB Protocol) traffic. An attacker operating a malicious IIOP server can send specially crafted requests to a vulnerable WebSphere instance, inducing the application to load and instantiate arbitrary classes. This primitive effectively allows for remote code execution, as the attacker can manipulate the application environment to execute arbitrary code or bypass security controls. Defenders should prioritize patching, as this vulnerability carries a CVSS 3.1 base score of 8.1.

## Impact

Successful exploitation allows for unauthenticated remote code execution on affected WebSphere Application Server instances. This impact potentially grants an attacker full control over the application server process, enabling data exfiltration, service disruption, or further lateral movement within the network. This affects enterprise organizations utilizing IBM WebSphere for critical Java-based business applications.

## Recommendation

Prioritize the application of official security patches from IBM for WebSphere Application Server and the associated IBM SDK for Java Technology Edition. Consult the IBM security bulletin at https://www.ibm.com/support/pages/node/7282446 for specific fix levels. As an immediate measure, restrict network access to the IIOP port (typically 2809) to trusted management segments only.
