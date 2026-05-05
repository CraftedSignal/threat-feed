---
title: Microsoft 365 Copilot Jailbreak Attempts via Prompt Injection
slug: 2024-01-03-m365-copilot-jailbreak
description: The detection identifies attempts to jailbreak Microsoft 365 Copilot through prompt injection techniques that attempt to circumvent built-in safety controls by manipulating rules, bypassing system commands, or requesting AI impersonation.
date: "2024-01-03T12:00:00Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - prompt-injection
  - ai-jailbreak
  - m365
  - copilot
vendors:
  - Microsoft
products:
  - M365 Copilot
references:
  - https://www.splunk.com/en_us/blog/artificial-intelligence/m365-copilot-log-analysis-splunk.html
rules:
  - title: Detect M365 Copilot Jailbreak Attempts via Keywords
    description: Detects M365 Copilot jailbreak attempts through prompt injection techniques using keywords.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: Detect M365 Copilot Amoral Impersonation Attempts
    description: Detects M365 Copilot jailbreak attempts using prompt injection with amoral impersonation requests.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
  - title: Detect M365 Copilot Rule Injection Attempts
    description: Detects M365 Copilot jailbreak attempts using rule injection techniques.
    platform: sigma
    severity: high
    tactics:
      - defense_evasion
    data_sources:
      - webserver
      - linux
rules_count: 3
---

Microsoft 365 Copilot is susceptible to jailbreak attempts via prompt injection, where users craft specific prompts designed to bypass or override safety controls. These attacks involve injecting malicious instructions into user prompts to manipulate the AI's behavior, potentially leading to the disclosure of sensitive information, the generation of harmful content, or the execution of unauthorized actions. The attacks leverage techniques like rule manipulation, system bypass commands, and AI impersonation requests, attempting to circumvent built-in safety mechanisms. Successful jailbreaks can compromise the integrity and security of Copilot, enabling threat actors to exploit the AI for malicious purposes.

## Attack Chain

1. An attacker crafts a malicious prompt containing specific keywords and phrases designed to manipulate Copilot's behavior.
2. The attacker injects the prompt into M365 Copilot through a standard user interface, like a chat window.
3. Copilot processes the prompt, attempting to interpret the user's intent.
4. If the prompt is successfully injected, Copilot's safety controls are bypassed or overridden due to prompt injection techniques.
5. Copilot generates a response based on the manipulated instructions in the prompt, potentially providing unauthorized access to information or functionality.
6. The attacker exfiltrates sensitive data or uses Copilot to perform actions outside its intended scope.
7. The attacker leverages the compromised Copilot to create and disseminate malicious content.

## Impact

Successful jailbreak attempts can lead to the disclosure of sensitive company data, generation of harmful or inappropriate content, and circumvention of organizational security policies. A single successful jailbreak can affect multiple users if the generated content is shared. If successful, internal copilots could be used to create phishing messages or generate code that gives the attacker a reverse shell on a machine. The risk is increased due to the widespread adoption of M365 Copilot across various industries.

## Recommendation

*   Enable M365 Exported eDiscovery Prompts logging to capture user interactions with Copilot, as this log source is crucial for detecting jailbreak attempts.
*   Deploy the Sigma rules provided in this brief to your SIEM to identify potential jailbreak attempts based on suspicious keywords and patterns in user prompts.
*   Implement filtering mechanisms based on the `m365_copilot_jailbreak_attempts_filter` macro to reduce false positives and focus on high-risk activities.
*   Monitor the `Subject_Title` field in the M365 eDiscovery prompt logs for the presence of jailbreak keywords and phrases such as "act as," "bypass," "ignore," "override," "pretend you are," and "rules=".
*   Investigate and remediate any identified jailbreak attempts to prevent further exploitation of M365 Copilot.
