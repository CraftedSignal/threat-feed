---
title: n8n Authenticated Code Execution Vulnerability
slug: 2026-07-n8n-auth-rce
description: A security advisory from CCCS highlights an authenticated code execution vulnerability (GHSA-rcv6-pvrj-4xcg) within the n8n Git node, affecting multiple versions prior to 1.123.67, 2.32.1, and 2.31.5, which could allow an authenticated attacker to execute arbitrary code on the host system.
date: "2026-07-22T18:08:49Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - authenticated-rce
  - workflow-automation
  - vulnerability
vendors:
  - n8n GmbH
products:
  - n8n versions prior to 1.123.67
  - n8n versions prior to 2.32.1
  - n8n versions prior to 2.31.5
mitre_ttps:
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Authenticated code execution in the n8n Git node
    confidence_band: high
references:
  - https://cyber.gc.ca/en/alerts-advisories/n8n-security-advisory-av26-733
  - https://github.com/n8n-io/n8n/security/advisories/GHSA-rcv6-pvrj-4xcg
  - https://github.com/n8n-io/n8n/security
---

The Canadian Centre for Cyber Security (CCCS) has issued an advisory regarding an authenticated code execution vulnerability (GHSA-rcv6-pvrj-4xcg) affecting the n8n workflow automation platform. Specifically, this flaw resides in the n8n Git node and impacts versions prior to 1.123.67, 2.32.1, and 2.31.5. An attacker who has already gained authenticated access to an n8n instance could exploit this vulnerability to execute arbitrary code on the underlying server. Given n8n's function in automating various tasks and integrating disparate systems, a successful compromise could lead to significant unauthorized access to data, system control, or disruption of critical business operations. Organizations leveraging vulnerable n8n versions are strongly advised to apply the recommended updates immediately to mitigate this risk.

## Attack Chain

1. An attacker obtains valid authentication credentials for an n8n instance, either through brute-force, phishing, or other means.
2. The authenticated attacker then accesses the n8n web interface to create or modify an existing workflow.
3. Within the workflow editor, the attacker specifically targets and configures an n8n Git node.
4. The attacker injects malicious commands or code into a parameter or field within the Git node's configuration that is not properly sanitized.
5. When the workflow containing the malicious Git node configuration is executed, the injected commands are processed and executed by the underlying operating system with the privileges of the n8n application.
6. This successful execution allows the attacker to achieve arbitrary code execution on the host server, enabling potential data exfiltration, further system compromise, or deployment of additional malware.

## Impact

A successful exploitation of this authenticated code execution vulnerability grants an attacker the ability to run arbitrary commands on the server hosting the n8n instance. This level of access can lead to severe consequences, including full compromise of the n8n application and its data, unauthorized access to sensitive information flowing through integrated workflows, modification or deletion of critical business data, and disruption of automated processes. Furthermore, an attacker could leverage this initial foothold for lateral movement within the network, potentially compromising other systems and expanding the scope of the breach.

## Recommendation

* **Apply Patches**: Immediately upgrade all affected n8n instances to version 1.123.67, 2.32.1, or 2.31.5, or a newer stable release. This directly remediates the authenticated code execution vulnerability (GHSA-rcv6-pvrj-4xcg).
* **Review Advisories**: Consult the n8n security advisories (available via the references section) for any additional mitigation steps or specific configuration changes recommended by the vendor.
* **Log Monitoring**: Enable robust process creation and network connection logging on the host system running n8n. Monitor these logs for any unusual or unauthorized processes launched by the n8n application's user account, or unexpected outbound network connections originating from n8n.
