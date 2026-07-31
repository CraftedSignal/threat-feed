---
title: Apache Cassandra JavaScript User-Defined Function Execution
slug: 2026-07-cassandra-javascript-udf
description: Adversaries can exploit the creation of JavaScript-based user-defined functions in Apache Cassandra to escape the Nashorn sandbox and achieve remote code execution, particularly when vulnerable to CVE-2021-44521.
date: "2026-07-31T19:10:38Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*
tags:
  - vulnerability
  - execution
  - cassandra
  - cql
  - sandbox-escape
vendors:
  - Apache
products:
  - Cassandra
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Identifies Cassandra Query Language statements that create a JavaScript user-defined function.
    confidence_band: high
cves:
  - id: CVE-2021-44521
    cvss: 9.1
    epss: 0.54727
references:
  - https://jfrog.com/blog/cve-2021-44521-exploiting-apache-cassandra-user-defined-functions-for-remote-code-execution/
  - https://nvd.nist.gov/vuln/detail/CVE-2021-44521
rules:
  - title: Detect Cassandra JavaScript UDF Creation
    description: Detects the creation of JavaScript-based user-defined functions via CQL as these are often used in sandbox escape attempts targeting CVE-2021-44521.
    platform: sigma
    severity: high
    tactics:
      - execution
    techniques:
      - T1059.007
    data_sources:
      - network_connection
rules_count: 1
---

This threat involves the abuse of Apache Cassandra's user-defined function (UDF) capability to execute arbitrary operating-system commands. By creating UDFs written in JavaScript, an attacker can leverage vulnerabilities such as CVE-2021-44521 to escape the Nashorn JavaScript sandbox. When Cassandra is configured with unsafe thread settings for scripted UDFs, this mechanism allows for full remote code execution on the database server. Defenders must monitor for unauthorized 'CREATE FUNCTION' operations within Cassandra Query Language (CQL) traffic. This technique is particularly dangerous because it grants the attacker code execution context with the privileges of the Cassandra database service, potentially leading to full system compromise, data exfiltration, or persistence within the cluster.

## Attack Chain

1. Attacker gains access to the database or a client machine capable of sending CQL queries to the Cassandra cluster.
2. Attacker checks the Cassandra configuration for 'enable_scripted_user_defined_functions' and 'enable_user_defined_functions_threads' to determine exploitability.
3. Attacker crafts a 'CREATE FUNCTION' CQL statement specifying the 'javascript' language.
4. The malicious function body is crafted to include Java reflection or class loading calls designed to bypass the Nashorn sandbox, targeting CVE-2021-44521.
5. The attacker executes the crafted CQL statement against the target keyspace.
6. The Cassandra engine parses the statement and initializes the malicious JavaScript function within the database service context.
7. The attacker invokes the UDF, triggering the sandbox escape and executing the attacker's payload (e.g., shell commands) on the host OS.
8. Final objective achieved: remote command execution, potentially leading to data exfiltration or internal network reconnaissance.

## Impact

Successful exploitation allows unauthenticated or unauthorized users to achieve full remote code execution on the underlying database host. This impacts the confidentiality, integrity, and availability of the database, posing a high risk to any data stored within the Cassandra cluster. The ability to escape the sandbox allows an attacker to move from the database layer to the operating system layer, facilitating further lateral movement within the network.

## Recommendation

- Patch Apache Cassandra installations to a version that addresses CVE-2021-44521.
- Disable 'enable_scripted_user_defined_functions' in the 'cassandra.yaml' configuration file if UDFs are not required for business operations.
- Deploy network traffic monitoring to detect cleartext CQL 'CREATE FUNCTION' commands containing 'language javascript'.
- Implement stringent role-based access control (RBAC) to restrict the ability to create UDFs to only highly trusted and verified administrative accounts.
- Review cluster audit logs for unexpected or unauthorized UDF creation attempts.
