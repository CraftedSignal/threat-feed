---
title: Suna Broken Access Control Vulnerability (CVE-2026-66027)
slug: 2026-07-suna-broken-access-control
description: A broken access control vulnerability in Suna's message queue API allows authenticated attackers to gain unauthorized access to and manipulate queue resources belonging to other users by exploiting missing ownership and account isolation checks. This exploit enables attackers to read all users' pending prompt queues, read or delete individual sessions, and inject arbitrary prompts into another user's session, which causes the background drainer to forward malicious messages to the victim's AI agent using their credentials and permissions, leading to potential data manipulation, unauthorized actions, or further compromise.
date: "2026-07-24T16:25:53Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - broken-access-control
  - vulnerability
  - suna
  - ai
  - message-queue
vendors:
  - Suna
products:
  - Suna < 0.9.102
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: authenticated attackers to access and manipulate queue resources
    confidence_band: high
  - tactic_id: TA0009
    tactic_name: Collection
    technique_id: T1005
    technique_name: Data from Local System
    evidence: Attackers can read pending prompt queues of all users
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1565
    technique_name: Data Manipulation
    evidence: read or delete individual sessions, and inject arbitrary prompts into another user's session queue
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: inject arbitrary prompts into another user's session queue, causing the background drainer to forward malicious messages to the victim's running AI agent with the victim's credentials and permissions.
    confidence_band: high
cves:
  - id: CVE-2026-66027
    cvss: 8.3
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-66027
---

A critical broken access control vulnerability, identified as CVE-2026-66027, has been discovered in Suna versions prior to 0.9.102. This flaw resides within the application's message queue API, allowing authenticated attackers to bypass intended security boundaries. Exploiting missing ownership and account isolation checks, an attacker can access and manipulate message queue resources belonging to other users. This grants the ability to read pending prompt queues for all users, read or delete individual user sessions, and crucially, inject arbitrary prompts into another user's session queue. This injection can cause Suna's background drainer to forward these malicious messages to the victim's running AI agent, which then executes them with the victim's credentials and permissions. The vulnerability poses a significant risk for data manipulation, unauthorized actions, and potential broader system compromise through the abused AI agent.

## Attack Chain

1. An authenticated attacker utilizes their legitimate Suna user account to interact with the message queue API.
2. The attacker identifies and leverages the broken access control vulnerability within the API by attempting to access resources outside their authorized scope.
3. The attacker exploits the missing ownership and account isolation checks to read pending prompt queues belonging to all users in the Suna instance.
4. The attacker further abuses the vulnerability to read or delete individual user sessions, disrupting or monitoring ongoing activities.
5. The attacker injects arbitrary malicious prompts into a target victim's session queue, masquerading as legitimate user input.
6. Suna's background drainer component processes the victim's session queue, inadvertently forwarding the injected malicious prompts to the victim's associated AI agent.
7. The victim's running AI agent executes the received malicious prompts, leveraging the victim's credentials and permissions.
8. This execution leads to unauthorized actions, data manipulation, or further compromise within the scope of the AI agent's access.

## Impact

Successful exploitation of CVE-2026-66027 allows authenticated attackers to achieve significant unauthorized access and control over other users' data and AI agent functionalities. Attackers can covertly monitor all users' pending prompt queues, delete active sessions, and inject commands directly into AI agents, effectively operating with the victim's privileges. This could lead to sensitive data exfiltration, execution of malicious tasks, unauthorized modifications to AI agent behavior, or even a complete compromise of systems accessible by the AI agent. The lack of proper isolation checks means a single compromised authenticated account can be leveraged to impact the entire Suna deployment.

## Recommendation

* Patch CVE-2026-66027 immediately by upgrading Suna to version 0.9.102 or newer to address the broken access control vulnerability.
* Review access logs for the Suna message queue API for any unusual or unauthorized access patterns, particularly attempts to read or delete sessions of other users.
* Monitor the activity of AI agents for any unexpected or malicious actions that could indicate the injection of arbitrary prompts, referencing potential TTPs like `T1059` and `T1565`.
