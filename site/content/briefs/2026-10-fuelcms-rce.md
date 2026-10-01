---
title: Remote Code Execution in Fuel CMS via CVE-2018-16763
slug: 2026-10-fuelcms-rce
description: An unauthenticated remote code execution vulnerability in Fuel CMS (CVE-2018-16763) allows attackers to inject and execute arbitrary PHP code via the filter parameter, leading to full system compromise.
date: "2026-10-01T05:39:17Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:thedaylightstudio:fuel_cms:*:*:*:*:*:*:*:*
vendors:
  - Thedaylightstudio
products:
  - Fuel CMS (<= 1.4.2)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The vulnerability stems from improper sanitization of the 'filter' parameter within the '/fuel/pages/select/' endpoint, which allows an attacker to inject and execute arbitrary PHP code.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: PHP'
    evidence: The exploit allows for the deployment of persistent web shells, arbitrary command execution under the context of the web server user.
    confidence_band: high
  - tactic_id: TA0003
    tactic_name: Persistence
    technique_id: T1105
    technique_name: Ingress Tool Transfer
    evidence: Automated scripts can be used to download files from the target system to the attacker machine.
    confidence_band: high
cves:
  - id: CVE-2018-16763
    cvss: 9.8
    epss: 0.82937
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2018-16763
  - https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4
  - https://sploitus.com/exploit?id=KITPLOIT:TOOLS-GITHUB-P0DALIRIUS-CVE-2018-16763-FUELCMS-1.4.1-RCE
rules:
  - title: Detect CVE-2018-16763 Exploitation Attempt
    description: Detects exploitation attempts against Fuel CMS by monitoring requests to the vulnerable endpoint with shell-related payloads in the filter parameter.
    platform: sigma
    severity: high
    tactics:
      - execution
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
    - action: Upgrade Fuel CMS to version > 1.4.2
      owner: IT Operations
      due: 24h
      evidence: Source advisory states Fuel CMS 1.4.2 and earlier are affected.
  hunt_leads:
    - lead: Search web logs for requests to /fuel/pages/select/ with suspicious PHP functions in the filter query parameter.
      technique_id: T1190
      data_needed:
        - Web server access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit uses /fuel/pages/select/ to execute arbitrary PHP code.
  mitigation_plan:
    - priority: immediate
      action: Deploy WAF rules to block requests to /fuel/pages/select/ containing common PHP execution keywords.
      owner: SOC
      addresses: CVE-2018-16763
      evidence: Exploit uses the 'filter' parameter as an entry point for arbitrary code execution.
---

Fuel CMS versions 1.4.2 and earlier contain a critical remote code execution (RCE) vulnerability, tracked as CVE-2018-16763. The vulnerability exists due to improper input sanitization in the 'filter' parameter within the '/fuel/pages/select/' endpoint. Unauthenticated attackers can leverage this flaw to perform PHP code injection by crafting specific HTTP requests that utilize 'eval' or other execution primitives. Recent disclosure of functional exploit scripts on platforms such as Sploitus significantly increases the risk of exploitation for any internet-facing instances that remain unpatched. Successful exploitation allows for the deployment of persistent web shells, arbitrary command execution under the context of the web server user, and unauthorized access to sensitive system files.

## Attack Chain

1. Attacker identifies a target server running an outdated version of Fuel CMS (1.4.2 or earlier).
2. Attacker sends a crafted HTTP GET or POST request to the '/fuel/pages/select/' endpoint.
3. The request includes a malicious payload injected into the 'filter' query parameter (e.g., using 'file_put_contents' to create a file).
4. The Fuel CMS application unsafely evaluates the input via an internal 'eval' or similar function, executing the attacker's PHP code.
5. The execution results in the creation of a persistent PHP web shell file on the web server's filesystem.
6. Attacker sends follow-up requests to the newly uploaded web shell to execute arbitrary system commands (e.g., 'id', 'ls').
7. Attacker uses the web shell to exfiltrate sensitive files, such as '/etc/passwd', to their remote machine.

## Impact

Successful exploitation of CVE-2018-16763 provides unauthenticated remote code execution. Attackers can gain complete control over the web application and the underlying server, potentially leading to data exfiltration, service disruption, and further lateral movement within the network. Given the ease of exploitation, any exposed Fuel CMS instance is at high risk of automated compromise.

## Recommendation

Prioritized, concrete actions for detection engineering and security teams:
- Immediately upgrade Fuel CMS to a version later than 1.4.2 to address the underlying vulnerability.
- Implement Web Application Firewall (WAF) rules to inspect incoming HTTP requests for suspicious patterns in the 'filter' parameter of '/fuel/pages/select/', specifically looking for PHP function keywords like 'eval', 'file_put_contents', or common shell metacharacters.
- Monitor web server logs for HTTP requests containing abnormal URL query strings or payloads targeting the specified endpoint.
- Review filesystem integrity for unexpected .php files created in the application's root or web-accessible directories, which may indicate the presence of a web shell.
- Deploy the Sigma rules below to identify and block exploitation attempts.
