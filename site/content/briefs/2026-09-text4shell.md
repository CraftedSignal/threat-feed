---
title: Critical Remote Code Execution in Apache Commons Text (CVE-2022-42889)
slug: 2026-09-text4shell
description: CVE-2022-42889, or Text4Shell, is a critical remote code execution vulnerability in Apache Commons Text versions 1.5-1.9 that allows attackers to execute arbitrary code via malicious string lookups.
date: "2026-09-23T17:57:29Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:commons_text:*:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:bluexp:-:*:*:*:*:*:*:*
  - cpe:2.3:a:juniper:security_threat_response_manager:*:*:*:*:*:*:*:*
  - cpe:2.3:a:juniper:security_threat_response_manager:7.5.0:-:*:*:*:*:*:*
  - cpe:2.3:a:juniper:security_threat_response_manager:7.5.0:up1:*:*:*:*:*:*
  - cpe:2.3:a:juniper:security_threat_response_manager:7.5.0:up2:*:*:*:*:*:*
  - cpe:2.3:a:juniper:security_threat_response_manager:7.5.0:up3:*:*:*:*:*:*
tags:
  - remote-code-execution
  - java
  - apache
vendors:
  - Apache
products:
  - Commons Text (1.5-1.9)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability can be exploited remotely by sending a specially crafted string to a vulnerable application via query parameters.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: The script interpolator allows arbitrary command execution via Java Runtime exec.
    confidence_band: high
cves:
  - id: CVE-2022-42889
    cvss: 9.8
    epss: 0.99931
references:
  - https://securitylab.github.com/advisories/GHSL-2022-018_Apache_Commons_Text/
  - https://www.rapid7.com/blog/post/2022/10/17/cve-2022-42889-keep-calm-and-stop-saying-4shell/
  - https://nvd.nist.gov/vuln/detail/CVE-2022-42889
rules:
  - title: Detect CVE-2022-42889 Exploitation - Text4Shell Payload in HTTP Requests
    description: Detects exploitation attempts of CVE-2022-42889 by monitoring for characteristic string interpolation prefixes in HTTP request parameters.
    platform: sigma
    severity: high
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
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Run dependency scan to identify all software using Apache Commons Text 1.5-1.9.
      owner: IT Operations
      due: 24h
      evidence: Vulnerability has a CVSS score of 9.8.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Apache Commons Text to version 1.10.0 or higher.
      owner: IT Operations
      addresses: CVE-2022-42889
      evidence: Source explicitly identifies v1.10.0 as the patched version.
---

CVE-2022-42889, widely known as Text4Shell, is a remote code execution (RCE) vulnerability affecting Apache Commons Text versions 1.5 through 1.9. The vulnerability arises from the default behavior of the 'StringSubstitutor' interpolator object, which uses the 'StringLookupFactory' to perform string lookups. When an application passes unsanitized user-supplied input to the 'StringSubstitutor.replace()' or 'replaceIn()' methods, an attacker can provide a specially crafted string using the '${prefix:name}' syntax. 

If the application is running on an environment that supports specific lookups, such as 'script', 'dns', or 'url', an attacker can trigger arbitrary command execution or unauthorized network requests. While modern JDK versions have removed the Nashorn JavaScript engine, the vulnerability remains exploitable in environments where third-party script engines like JEXL are present in the classpath. Defenders should treat this as a high-priority risk for any Java-based applications utilizing these affected versions of the Apache Commons Text library.

## Attack Chain

1. Attacker identifies a web application utilizing Apache Commons Text (v1.5-1.9) that passes user input to 'StringSubstitutor.replace()'.
2. Attacker crafts a malicious payload using interpolation syntax, for example: '${script:javascript:java.lang.Runtime.getRuntime().exec('command')}'.
3. Attacker delivers the payload through a common web vector, such as an HTTP GET query parameter (e.g., '?data=${payload}') or a POST request body.
4. The vulnerable application receives the request and passes the malicious string to the 'StringSubstitutor' interpolation engine.
5. The library processes the '${script:...}' prefix, triggering the underlying scripting engine (Nashorn or JEXL).
6. The scripting engine executes the injected command with the privileges of the web application server process.
7. If successful, the attacker gains RCE, enabling lateral movement, data exfiltration, or further malware deployment.

## Impact

Successful exploitation allows for unauthenticated remote code execution, granting the attacker full control over the vulnerable server process. This vulnerability affects any enterprise Java ecosystem using the vulnerable versions of Apache Commons Text. Given the ubiquitous nature of this library, the potential scope includes a broad range of web applications, middleware, and backend services, leading to potential complete system compromise and data breach.

## Recommendation

1. Upgrade Apache Commons Text to version 1.10.0 or later immediately to eliminate the vulnerable interpolation behavior.
2. Deploy Web Application Firewall (WAF) rules to inspect incoming HTTP requests for suspicious patterns containing '${' followed by 'script:', 'dns:', or 'url:' prefixes.
3. Perform a dependency scan across all enterprise Java applications to identify and remediate instances of 'commons-text' versions 1.5-1.9 using SCA (Software Composition Analysis) tools.
4. Monitor application logs for unexpected system calls originating from the Java runtime process, particularly those invoking command shells like 'bash', 'sh', or 'cmd.exe'.
5. In environments where upgrading is not immediately feasible, implement strict input validation to prevent user-supplied data from reaching string interpolation methods.
