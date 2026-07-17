---
title: IBM Langflow OSS Remote Code Execution via Deserialization
slug: 2026-07-ibm-langflow-rce
description: IBM Langflow OSS versions 1.0.0 through 1.10.0 contain a critical deserialization vulnerability (CVE-2026-8476) in its disk-based caching mechanism, which uses Python's unsafe `pickle.loads()` function without proper validation, allowing attackers to process malicious pickle payloads and achieve arbitrary code execution with the privileges of the Langflow server process, leading to complete system compromise.
date: "2026-07-17T20:20:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - deserialization
  - python
  - langflow
vendors:
  - IBM
products:
  - Langflow OSS 1.0.0
  - Langflow OSS 1.1.0
  - Langflow OSS 1.2.0
  - Langflow OSS 1.3.0
  - Langflow OSS 1.4.0
  - Langflow OSS 1.5.0
  - Langflow OSS 1.6.0
  - Langflow OSS 1.7.0
  - Langflow OSS 1.8.0
  - Langflow OSS 1.9.0
  - Langflow OSS 1.10.0
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers who can influence cached data through file system access, malicious workflow inputs, custom components, or API manipulation can achieve complete system compromise with the privileges of the Langflow server process.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Python's unsafe pickle.loads() function to deserialize cached objects from disk without validation, integrity verification, or authentication, enabling arbitrary code execution when malicious pickle payloads are processed.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: achieve complete system compromise with the privileges of the Langflow server process.
    confidence_band: high
cves:
  - id: CVE-2026-8476
    cvss: 9.9
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-8476
---

IBM Langflow OSS, specifically versions 1.0.0 through 1.10.0, is affected by a critical remote code execution vulnerability, identified as CVE-2026-8476. The flaw resides within the `AsyncDiskCache` class, which is part of the application's disk-based caching mechanism. This class insecurely employs Python's `pickle.loads()` function to deserialize cached objects without implementing validation, integrity verification, or authentication measures. This critical oversight allows an attacker to inject and process specially crafted malicious pickle payloads. By influencing cached data through various methods, such as direct file system access, malicious workflow inputs, custom components, or API manipulation, threat actors can trigger arbitrary code execution. Successful exploitation results in complete system compromise with the privileges of the Langflow server process.

## Attack Chain

1. An attacker gains the ability to influence or replace data within Langflow's disk-based cache. This can be achieved via malicious workflow inputs, custom component uploads, API manipulation, or direct file system access to the cache directory.
2. The attacker crafts a malicious Python pickle payload designed to execute arbitrary system commands upon deserialization.
3. The crafted malicious pickle payload is injected into or replaces legitimate cached data within Langflow's `AsyncDiskCache` directory on the server.
4. The Langflow server process attempts to read and deserialize the manipulated cached object from disk using the vulnerable `pickle.loads()` function.
5. During the insecure deserialization process, the malicious pickle payload is executed on the host system.
6. The attacker achieves arbitrary code execution with the privileges of the Langflow server process.
7. The attacker leverages the achieved code execution to gain complete system compromise and potentially establish persistence.

## Impact

Successful exploitation of CVE-2026-8476 leads to critical consequences, including arbitrary code execution and complete system compromise. Attackers can gain control over the Langflow server, allowing them to steal sensitive data, deploy further malware, disrupt operations, or use the compromised server as a foothold for lateral movement within the network. The vulnerability's high CVSS score of 9.9 reflects the severe impact and ease of exploitation.

## Recommendation

* Immediately patch IBM Langflow OSS installations to a version beyond 1.10.0 to remediate CVE-2026-8476.
* Implement strict access controls for Langflow instances, ensuring only authorized and trusted users can provide workflow inputs or custom components.
* Monitor file system write events to Langflow's cache directories for unusual modifications or injections of suspicious files.
* Review all API endpoints that could allow manipulation of cached data or workflow inputs for potential abuse, especially those mentioned in the overview.
