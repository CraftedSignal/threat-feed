---
title: Remote Command Injection in SabyasachiRana WebMap
slug: 2026-09-webmap-command-injection
description: An unauthenticated remote OS command injection vulnerability in SabyasachiRana WebMap's nmap_newscan function allows attackers to execute arbitrary commands via the target/params argument.
date: "2026-09-15T01:37:43Z"
type: threat
types:
  - threat
severities:
  - high
exploited: true
cpes:
  - cpe:2.3:a:sabyasachirana:webmap:*:*:*:*:*:*:*:*
vendors:
  - SabyasachiRana
products:
  - WebMap (<= 8b95fe4dc301a3c09ddf145b895de0bf9f8d2a25)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Such manipulation of the argument target/params leads to os command injection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: The attack may be launched remotely.
    confidence_band: high
cves:
  - id: CVE-2026-90843
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-90843
rules:
  - title: Detects CVE-2026-90843 Exploitation - WebMap Command Injection
    description: Detects exploitation attempts against CVE-2026-90843 by identifying shell metacharacters within the target or params arguments typically used in nmap scanning requests.
    platform: sigma
    severity: high
    tactics:
      - execution
      - initial_access
    techniques:
      - T1203
    data_sources:
      - webserver
rules_count: 1
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch WebMap to 3d52f65803a2716bff14d938352c6fef45b0cfb6
      owner: IT Operations
      due: 24h
      evidence: Source explicitly mandates this patch to remediate the issue.
  hunt_leads:
    - lead: Search web logs for semicolon or pipe symbols in target or parameter arguments
      technique_id: T1203
      data_needed:
        - webserver_access_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability analysis indicates command injection via these specific arguments.
  mitigation_plan:
    - priority: immediate
      action: Patch affected WebMap components
      owner: IT Operations
      addresses: CVE-2026-90843
      evidence: Source states issue fixed by patch 3d52f65803a2716bff14d938352c6fef45b0cfb6
  gaps:
    - Lack of specific exploit payloads observed in the wild
---

CVE-2026-90843 describes a critical remote code execution vulnerability identified in the SabyasachiRana WebMap application. The vulnerability exists within the nmap_newscan function, located in the functions_nmap.py file. It is caused by improper sanitization of the target/params argument, which is passed directly to system-level calls. An attacker can exploit this by submitting crafted input to the target or parameters field of the New Nmap Scan Handler, enabling them to execute arbitrary OS commands on the host server. The vulnerability is exploitable remotely without authentication. Public disclosure of the exploit has increased the likelihood of active exploitation. Organizations using versions of WebMap up to commit 8b95fe4dc301a3c09ddf145b895de0bf9f8d2a25 should immediately apply the vendor-provided patch 3d52f65803a2716bff14d938352c6fef45b0cfb6 to mitigate this risk.

## Attack Chain

1. Attacker identifies a target running a vulnerable version of SabyasachiRana WebMap exposed to the internet.
2. Attacker probes the application to locate the New Nmap Scan Handler feature.
3. Attacker crafts an HTTP request targeting the functionality served by functions_nmap.py.
4. Attacker injects malicious OS command syntax into the target or params argument fields.
5. The application passes the unsanitized input to the nmap_newscan function.
6. The underlying OS executes the attacker-supplied command with the privileges of the WebMap service.
7. Attacker achieves remote code execution for potential post-exploitation activities.

## Impact

Successful exploitation allows for full remote command execution on the host server, potentially leading to unauthorized data exfiltration, internal network lateral movement, or complete system compromise. The vulnerability affects all users of the WebMap project prior to the application of the specified security patch.

## Recommendation

- Upgrade the WebMap application to at least commit 3d52f65803a2716bff14d938352c6fef45b0cfb6 immediately.
- Audit webserver access logs for POST requests directed at endpoints associated with the New Nmap Scan Handler containing shell metacharacters such as semicolon, pipe, or backticks in the request body.
- Implement strict input validation on the application front-end for all target and parameter fields passed to scanning components.
- Restrict network access to the WebMap administrative interface to trusted IP addresses only.
