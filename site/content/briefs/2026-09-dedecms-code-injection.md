---
title: Remote Code Injection Vulnerability in DedeCMS
slug: 2026-09-dedecms-code-injection
description: DedeCMS versions up to 5.7.118 contain a code injection vulnerability in the plus/mytag_js.php file that allows unauthenticated remote attackers to execute arbitrary code via the aid argument.
date: "2026-09-20T12:21:13Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:dedecms:dedecms:*:*:*:*:*:*:*:*
vendors:
  - DedeCMS
products:
  - DedeCMS (<= 5.7.118)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability is publicly known and can be exploited remotely by an unauthenticated attacker.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The manipulation of the argument aid results in code injection.
    confidence_band: high
cves:
  - id: CVE-2026-94004
    cvss: 7.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-94004
rules:
  - title: Detects CVE-2026-94004 Exploitation - Code Injection in DedeCMS
    description: Detects exploitation attempts against CVE-2026-94004 where an attacker sends a crafted request to plus/mytag_js.php to inject code via the aid parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all web servers to identify DedeCMS 5.7.118 and below.
      owner: IT Operations
      due: 24h
      evidence: Affected products list includes DedeCMS <= 5.7.118.
  mitigation_plan:
    - priority: immediate
      action: Upgrade DedeCMS to a patched version beyond 5.7.118.
      owner: IT Operations
      addresses: CVE-2026-94004
      evidence: Reported vulnerability affects versions up to 5.7.118.
---

DedeCMS versions up to and including 5.7.118 are vulnerable to a remote code injection flaw located in the 'plus/mytag_js.php' file. The vulnerability stems from improper input validation of the 'aid' argument, which allows an unauthenticated attacker to inject and execute arbitrary code on the target server. Because the vulnerability is reachable via standard HTTP GET requests to the identified file, it poses a high risk to installations of the affected content management system. Proof-of-concept exploit code has been publicly disclosed, increasing the likelihood of opportunistic exploitation by threat actors. Organizations hosting DedeCMS should verify their version and restrict access to the 'plus/mytag_js.php' endpoint or apply vendor-provided patches.

## Impact

Successful exploitation of this vulnerability results in unauthenticated remote code execution (RCE) on the web server hosting DedeCMS. This allows an attacker to gain full control over the application, access sensitive database information, exfiltrate user data, or use the compromised server as a pivot point for further lateral movement within the network.

## Recommendation

* Prioritize the identification of all internet-facing DedeCMS instances in the environment.
* Upgrade all DedeCMS installations to a version beyond 5.7.118 immediately.
* Implement web application firewall (WAF) rules to block HTTP requests to '/plus/mytag_js.php' containing suspicious characters (e.g., shell metacharacters or alphanumeric strings designed to trigger code execution) in the 'aid' parameter.
* Review web server logs for HTTP requests targeting the 'plus/mytag_js.php' file with unusual values in the query string to identify attempted exploitation.
