---
title: Unauthenticated RCE in AgenticSeek via Command Injection
slug: 2026-08-agenticseek-rce
description: AgenticSeek commit fc242c7 is vulnerable to unauthenticated remote code execution via a misconfigured /query API endpoint that allows arbitrary shell command injection through the BashInterpreter module.
date: "2026-08-14T00:05:24Z"
type: advisory
types:
  - advisory
severities:
  - critical
products:
  - AgenticSeek
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: AgenticSeek (commit fc242c7) contains an unauthenticated remote code execution vulnerability that allows any network-adjacent attacker to execute arbitrary commands by submitting crafted queries to the unprotected POST /query API endpoint.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.004
    technique_name: 'Command and Scripting Interpreter: Unix Shell'
    evidence: Attackers can send unauthenticated HTTP requests that cause the autonomous agent to generate and execute shell commands through BashInterpreter using subprocess.Popen with shell=True.
    confidence_band: high
cves:
  - id: CVE-2026-72776
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-72776
rules:
  - title: Detect CVE-2026-72776 Exploitation - Command Injection via AgenticSeek Query
    description: Detects exploitation attempts against AgenticSeek where HTTP POST requests to /query contain shell metacharacters indicative of command injection.
    platform: sigma
    severity: critical
    tactics:
      - execution
      - initial_access
    techniques:
      - T1059.004
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
    - action: Restrict network access to the AgenticSeek host on port 7777
      owner: IT Operations
      due: 24h
      evidence: Unauthenticated RCE vulnerability via POST /query
  hunt_leads:
    - lead: Search web logs for POST requests to /query containing shell metacharacters (; | && || ` $())
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Vulnerability allows unauthenticated command injection via /query endpoint
  mitigation_plan:
    - priority: immediate
      action: Implement authentication and sanitize inputs for BashInterpreter
      owner: IT Operations
      addresses: CVE-2026-72776
      evidence: Vulnerability arises from subprocess.Popen(shell=True)
---

AgenticSeek (commit fc242c7) contains a critical unauthenticated remote code execution vulnerability. The application exposes an API endpoint at POST /query which is bound to all network interfaces (0.0.0.0:7777) and configured with wildcard Cross-Origin Resource Sharing (CORS). The vulnerability stems from the application's reliance on the BashInterpreter component, which executes user-supplied queries using subprocess.Popen with shell=True and safety=False. Because the internal command blocklist is incomplete and easily bypassed, a network-adjacent attacker can submit crafted HTTP POST requests to trigger the execution of arbitrary operating system commands on the host. This vulnerability allows for full system compromise without any prior authentication or authorization.

## Impact

The vulnerability carries a CVSS v3.1 base score of 9.8, indicating the highest level of severity. Successful exploitation results in unauthenticated, host-level code execution. In environments where AgenticSeek is deployed with network-wide accessibility, any attacker with network adjacency can gain immediate control over the host machine, leading to potential data exfiltration, lateral movement within the network, or the installation of persistent malicious software.

## Recommendation

1. Restrict network access to the AgenticSeek API endpoint at port 7777 to trusted management networks only, ensuring it is not reachable from untrusted segments or the public internet.
2. Implement strict authentication middleware for the /query API endpoint to ensure all requests are validated before being processed by the agent.
3. Update the AgenticSeek implementation to utilize subprocess.run with shell=False and pass arguments as a list to prevent shell metacharacter injection.
4. Replace the existing command blocklist with a robust, allowlist-based validation mechanism that strictly defines permissible commands and parameters.
5. Deploy the suggested Sigma rule to monitor for suspicious POST requests targeting the /query endpoint that contain shell metacharacters.
