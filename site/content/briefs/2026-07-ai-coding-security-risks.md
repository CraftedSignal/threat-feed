---
title: Security Risks Associated with AI Coding Tools, Including GhostApproval Vulnerability
slug: 2026-07-ai-coding-security-risks
description: The adoption of AI coding tools introduces significant security risks, such as the generation of vulnerable code with OWASP Top 10 flaws, the inadvertent leakage of sensitive secrets and hardcoded credentials, and supply chain compromise via 'slopsquatting,' alongside specific vulnerabilities like 'GhostApproval' which allows remote code execution on developer machines.
date: "2026-07-10T13:01:10Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - ai
  - coding-tools
  - supply-chain
  - vulnerability
  - rce
  - credential-exposure
vendors:
  - Amazon
  - Anthropic
  - Augment
  - Cursor
  - Google
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1195
    technique_name: Supply Chain Compromise
    evidence: There's also the issue of 'slopsquatting' — approximately 20% of AI-generated code samples reference packages that don't exist, and attackers publish malicious packages with those hallucinated names in order to target organizations.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: Wiz this week unveiled GhostApproval, a vulnerability pattern affecting six of the top AI coding assistants... In each case, a malicious repository can trick the agent into accessing arbitrary files outside the workspace sandbox, potentially achieving remote code execution on the developer's machine.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    evidence: There's also a longstanding issue of AI-generated code spilling secrets and hardcoded credentials... According to our research, the use of AI coding assistants increases the secrets incidence rate by approximately 40%.
    confidence_band: high
references:
  - https://www.darkreading.com/application-security/ai-coding-security-risks-productivity-gains
---

The widespread adoption of AI coding tools, with 91% of organizations using two or more and 54% using three or more, presents considerable security challenges despite perceived productivity gains. Research indicates that 45% of AI-generated code samples contain OWASP Top 10 vulnerabilities, contributing to a new category of technical debt. A critical vulnerability pattern, named "GhostApproval," was recently disclosed by Wiz, affecting at least six major AI coding assistants, including Amazon Q Developer, Anthropic Claude Code, Augment, Cursor, Google Antigravity, and Windsurf. This vulnerability allows malicious repositories to trick AI agents into accessing arbitrary files outside the workspace sandbox, potentially leading to remote code execution (RCE) on developer machines. Additionally, AI coding tools have been linked to a 40% increase in leaked secrets compared to traditional workflows, with 64% of credentials found in public GitHub commits in 2022 still valid in January 2026. The phenomenon of "slopsquatting," where attackers publish malicious packages mimicking hallucinated dependencies from AI-generated code, further exacerbates supply chain risks.

## Attack Chain

1. An attacker crafts a repository containing malicious code or configuration designed to exploit vulnerabilities in AI coding assistants.
2. A developer integrates or uses an AI coding assistant to interact with the attacker-controlled malicious repository.
3. The malicious repository leverages the "GhostApproval" vulnerability to manipulate the AI agent, bypassing its intended sandbox boundaries.
4. The compromised AI agent is tricked into accessing arbitrary files on the developer's local system, outside of its designated workspace.
5. Through unauthorized file access and execution capabilities, the attacker achieves remote code execution on the developer's machine.
6. Successful exploitation can lead to credential theft, intellectual property exfiltration, or further lateral movement within the organization.

## Impact

The impact of these security risks ranges from significant financial costs due to remediation efforts to severe data breaches and intellectual property loss. Leaked credentials, often discovered and validated in public repositories, can remain active for years, providing persistent access for threat actors. The "GhostApproval" vulnerability poses a direct threat of remote code execution on developer workstations, which can serve as a pivot point for broader network compromise. "Slopsquatting" can introduce malicious dependencies into software, leading to supply chain attacks. Security teams are spending up to 40% of their time triaging false positives from AI-generated code, resulting in hundreds of thousands of dollars in unproductive expenditure and increased technical debt.

## Recommendation

* Implement secure code development practices, including regular security audits of AI-generated code for OWASP Top 10 vulnerabilities.
* Deploy GitGuardian or similar secret detection tools within CI/CD pipelines to identify and prevent the leakage of credentials as mentioned in the content.
* Ensure developers are aware of the risks associated with AI coding tools and are trained to verify AI-generated code before committing it.
* Patch CVE-XXXX-YYYY (if a specific CVE is assigned to GhostApproval) on all affected AI coding assistants immediately upon release from affected vendors.
* Monitor for unusual file access patterns from AI coding assistant processes as described in the "GhostApproval" vulnerability.
* Establish robust supply chain security measures to detect and prevent "slopsquatting" by verifying package sources and integrity.
