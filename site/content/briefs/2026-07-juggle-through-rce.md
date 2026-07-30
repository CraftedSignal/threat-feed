---
title: Remote Code Execution via Exposed H2 Database in Juggle Through
slug: 2026-07-juggle-through-rce
description: An unauthenticated remote code execution vulnerability in Juggle Through 1.6.0 allows attackers to leverage default credentials on the H2 database console to execute system-level commands.
date: "2026-07-30T21:31:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
tags:
  - remote-code-execution
  - vulnerability
  - cve-2026-67208
vendors:
  - Juggle
products:
  - Juggle Through (1.6.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An unauthenticated remote attacker can execute arbitrary OS commands by connecting to the exposed H2 database web console.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: Attacker can leverage the H2 CREATE ALIAS Runtime.exec() technique to execute arbitrary commands.
    confidence_band: high
cves:
  - id: CVE-2026-67208
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-67208
---

Juggle Through version 1.6.0 and earlier contains a critical remote code execution vulnerability stemming from an exposed H2 database console that remains accessible with default credentials. An unauthenticated attacker can navigate to the '/h2-console' endpoint of a Juggle Through installation, authenticate using the default credentials, and interact with the database management interface. By executing SQL statements, an attacker can leverage the H2 database's 'CREATE ALIAS' feature to bridge the application to the underlying host operating system. This allows for the execution of arbitrary commands via 'Runtime.exec()'. In standard containerized environments, such as the default Docker image provided by the vendor, this activity results in command execution with root-level privileges on the host or container, facilitating full system compromise.

## Attack Chain

1. Attacker performs reconnaissance to identify internet-facing endpoints running Juggle Through software.
2. Attacker probes the host for the presence of the default H2 database management console at the '/h2-console' URI path.
3. Attacker accesses the H2 console login page and authenticates using the default shipped vendor credentials.
4. Once authenticated, the attacker accesses the SQL query execution interface provided by the H2 console.
5. Attacker executes a 'CREATE ALIAS' SQL statement to register a Java method that invokes 'java.lang.Runtime.getRuntime().exec()'.
6. Attacker calls the newly created alias, passing the desired malicious system command as a parameter.
7. The H2 database service executes the command with the privileges of the Juggle Through process, typically root within the Docker container.
8. Attacker achieves command execution to perform lateral movement, exfiltration, or further system compromise.

## Impact

Successful exploitation of CVE-2026-67208 results in unauthenticated remote code execution with root privileges. This vulnerability impacts all installations of Juggle Through version 1.6.0 and earlier. Organizations deploying this software in containerized environments are at highest risk, as the process typically runs as root, granting an attacker full control over the container, potential escape vectors, and access to internal network resources or sensitive application data.

## Recommendation

Prioritize patching all Juggle Through instances to the latest secure version immediately. If patching is not feasible, restrict network access to the '/h2-console' endpoint to authorized internal management IP addresses via a reverse proxy or firewall. Disable or remove the H2 database console functionality if it is not required for production operations. Configure the application to run with non-root service account privileges to limit the potential impact of command execution.

## Rules

title: "Detect CVE-2026-67208 Exploitation - H2 Database Console Access"
description: "Detects unauthorized access or usage of the H2 database console associated with Juggle Through exploitation."
logsource:
 category: webserver
detection:
 selection:
 cs-uri-stem|contains: "/h2-console"
 condition: selection
level: high
tags:
 - attack.initial_access
 - attack.execution
 - attack.t1190
falsepositives:
 - "Legitimate administrative access from authorized IP addresses"
tests:
 positive:
 - name: "Access to H2 console endpoint"
 data:
 - cs-uri-stem: "/h2-console/login.do"
 cs-method: "GET"
 negative:
 - name: "Normal application traffic"
 data:
 - cs-uri-stem: "/api/v1/status"
 cs-method: "GET"
