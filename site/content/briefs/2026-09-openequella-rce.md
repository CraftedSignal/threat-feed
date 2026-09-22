---
title: Authenticated RCE in openEQUELLA via Deserialization Bypass
slug: 2026-09-openequella-rce
description: openEQUELLA versions prior to 2026.1.0 contain a critical authenticated remote code execution vulnerability involving insecure Java deserialization via the /invoker/* endpoint.
date: "2026-09-22T22:40:20Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:openequella:openequella:*:*:*:*:*:*:*:*
vendors:
  - openEQUELLA
products:
  - openEQUELLA (< 2026.1.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: openEQUELLA before 2026.1.0 contains an authenticated remote code execution vulnerability that allows any authenticated non-guest user to execute arbitrary code by exploiting Java deserialization
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker can bypass the class-name denylist... ultimately reaching a JNDI sink and enabling code execution.
    confidence_band: high
cves:
  - id: CVE-2026-67615
    cvss: 8.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67615
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Engineering
  immediate_actions:
    - action: Upgrade openEQUELLA to version 2026.1.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-67615 patch availability
  mitigation_plan:
    - priority: immediate
      action: Upgrade openEQUELLA to 2026.1.0
      owner: IT Operations
      addresses: CVE-2026-67615
      evidence: Source provided fixed version
---

openEQUELLA versions prior to 2026.1.0 are vulnerable to authenticated remote code execution (CVE-2026-67615). The flaw resides in the HTTP invoker endpoint (/invoker/*), which fails to safely handle Java deserialization. Authenticated non-guest users can exploit this by sending a specially crafted serialized object. The implementation uses a PluginAwareObjectInputStream with a class-name denylist; however, attackers bypass this restriction by nesting a malicious payload within a java.security.SignedObject. This wrapping forces the inner stream to be processed by a secondary ObjectInputStream that lacks the required filtering, allowing the payload to reach a JNDI sink. Successful exploitation results in arbitrary code execution within the context of the openEQUELLA service. This vulnerability highlights the risks associated with Java deserialization and the limitations of denylist-based security controls. Organizations using openEQUELLA should upgrade to version 2026.1.0 or later immediately.

## Attack Chain

1. Attacker obtains valid non-guest authenticated access to the target openEQUELLA instance.
2. Attacker prepares a malicious serialized Java object payload targeting a known JNDI sink.
3. Attacker wraps the malicious serialized object within a java.security.SignedObject.
4. Attacker sends an HTTP POST request to the application's /invoker/* endpoint containing the crafted object.
5. The application endpoint receives the request and triggers the PluginAwareObjectInputStream.
6. The initial deserialization processes the SignedObject; the embedded inner stream bypasses the class-name denylist filter.
7. The secondary ObjectInputStream deserializes the nested malicious payload.
8. The JNDI sink is triggered, leading to arbitrary code execution on the application server.

## Impact

Successful exploitation allows an authenticated attacker to execute arbitrary code on the underlying host, potentially leading to full system compromise, data theft, or lateral movement within the environment. This vulnerability affects all deployments of openEQUELLA prior to 2026.1.0. Given the high CVSS score of 8.8, immediate patching is recommended for all affected instances.

## Recommendation

1. Upgrade all openEQUELLA instances to version 2026.1.0 or later to mitigate CVE-2026-67615.
2. Monitor HTTP invoker traffic to the /invoker/* endpoint for unusual or excessively large serialized object payloads.
3. Restrict access to the openEQUELLA application to trusted users to reduce the potential for exploitation by malicious or compromised accounts.
