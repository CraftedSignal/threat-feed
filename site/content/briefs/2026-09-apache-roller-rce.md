---
title: Unauthenticated Remote Code Execution in Apache Roller via XML-RPC Deserialization
slug: 2026-09-apache-roller-rce
description: Apache Roller 6.1.5 is susceptible to unauthenticated remote code execution via insecure Java deserialization on the XML-RPC endpoint, which is triggered by an attacker-supplied 'ex:serializable' extension type before authentication is processed.
date: "2026-09-28T09:53:27Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache_software_foundation:apache_roller:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - rce
  - deserialization
  - apache-roller
vendors:
  - Apache Software Foundation
products:
  - Apache Roller (6.1.5)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2026-82384 is deserialization of untrusted data (CWE-502) on the XML-RPC endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Impact is RCE as the Tomcat/Roller OS user.
    confidence_band: high
cves:
  - id: CVE-2026-82384
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-82384
  - https://github.com/apache/roller/pull/171
rules:
  - title: Detects CVE-2026-82384 Exploitation - XML-RPC Deserialization Attempt
    description: Detects exploitation attempts against CVE-2026-82384 by monitoring for POST requests to XML-RPC endpoints containing the ex:serializable extension type.
    platform: sigma
    severity: critical
    tactics:
      - initial_access
    techniques:
      - T1190
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all Apache Roller instances and verify version 6.1.5.
      owner: IT Operations
      due: 24h
      evidence: Affected Apache Roller 6.1.5.
    - action: Patch all vulnerable Apache Roller instances to version 6.1.6 or later.
      owner: IT Operations
      due: 48h
      evidence: 'Remediation: Upgrade to Roller 6.1.6+.'
  mitigation_plan:
    - priority: immediate
      action: Block access to /roller-services/xmlrpc at the network perimeter or WAF.
      owner: IT Operations
      addresses: CVE-2026-82384
      evidence: 'Until patched: block /roller-services/xmlrpc at reverse proxy / WAF.'
---

Apache Roller 6.1.5 contains a critical vulnerability (CVE-2026-82384) allowing unauthenticated remote code execution (RCE) via the application's XML-RPC interface. The vulnerability resides within the `XmlRpcServlet`, which is configured with the `enabledForExtensions=true` parameter. This configuration instructs the underlying Apache ws-xmlrpc library to accept vendor-specific extensions, including `ex:serializable`, which carries base64-encoded Java serialized objects.

Crucially, this deserialization process occurs during the HTTP request handling phase, prior to the enforcement of authentication for Blogger or MetaWeblog APIs. Furthermore, the XML-RPC servlet mapping is active by default in the web.xml configuration, meaning even if an administrator disables XML-RPC via the application's administrative UI, the vulnerable code path remains exposed to unauthenticated exploitation. Attackers can leverage this primitive to achieve full RCE on the host server by providing a crafted gadget chain, typically generated via tools like 'ysoserial'.

## Attack Chain

1. The attacker performs reconnaissance to identify Apache Roller instances by scanning for standard paths such as `/roller-ui/` or `/roller-services/xmlrpc`.
2. The attacker fingerprints the application version to confirm the target is running the vulnerable 6.1.5 release.
3. The attacker prepares a serialized Java payload using a gadget chain appropriate for the application's classpath (e.g., Commons Collections).
4. The attacker crafts an XML-RPC request using the `text/xml` content type, embedding the malicious object within an `ex:serializable` extension tag.
5. The attacker sends a POST request to `/roller-services/xmlrpc` or `/roller/roller-services/xmlrpc`.
6. The `XmlRpcServlet` parses the XML body and automatically deserializes the embedded object before reaching the authentication logic.
7. The deserialization process executes arbitrary code within the context of the JVM process.
8. The attacker achieves full control over the application's data and potentially gains a pivot point into the underlying OS.

## Impact

Successful exploitation results in full unauthenticated remote code execution with the privileges of the Tomcat or Java application user. This impact includes the complete compromise of blog data, the ability to read or modify sensitive configuration files, and the potential for lateral movement within the environment. The vulnerability has been assigned a CVSS 3.1 score of 9.8, reflecting its high severity and ease of exploitation without user interaction or authentication.

## Recommendation

Prioritize the immediate upgrade of all Apache Roller instances to version 6.1.6 or later, which addresses CVE-2026-82384 by disabling extensions and tightening XML-RPC request handling. In environments where immediate patching is not possible, implement WAF or reverse proxy rules to strictly block access to the `/roller-services/xmlrpc` endpoint for all but known, authorized administrative IP addresses. Security teams should also audit their environments to identify all instances of Apache Roller by searching for common footprints such as the `/roller-ui/` directory or specific HTTP response headers.
