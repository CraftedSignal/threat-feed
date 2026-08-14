---
title: Datavane TIS XXE Vulnerability CVE-2026-69101
slug: 2026-08-datavane-tis-xxe
description: Datavane TIS v5.0.0 is vulnerable to XML external entity injection in the doEditWorkflow endpoint, allowing authenticated attackers to perform SSRF and exfiltrate sensitive local files.
date: "2026-08-14T16:12:17Z"
type: advisory
types:
  - advisory
severities:
  - high
tags:
  - web-vulnerability
  - xxe
  - ssrf
  - data-exfiltration
vendors:
  - Datavane
products:
  - TIS (v5.0.0)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Datavane TIS v5.0.0 contains an XML external entity (XXE) injection vulnerability that allows authenticated attackers to perform server-side request forgery.
    confidence_band: high
cves:
  - id: CVE-2026-69101
    cvss: 7.7
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-69101
rules:
  - title: Detects CVE-2026-69101 Exploitation - XXE via doEditWorkflow
    description: Detects attempts to exploit XXE in Datavane TIS by identifying XML DTD or entity declarations in POST requests to the workflow edit endpoint.
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
  priority: elevated
  owners:
    - IT Operations
    - Detection Engineering
  immediate_actions:
    - action: Patch Datavane TIS software
      owner: IT Operations
      due: 72h
      evidence: Vulnerability CVE-2026-69101 requires software update for remediation
    - action: Deploy web application firewall rules to inspect for XML entities
      owner: Detection Engineering
      due: 24h
      evidence: XXE vulnerability allows OOB exfiltration via taskScript payload
  mitigation_plan:
    - priority: immediate
      action: Restrict outbound network access from the Datavane TIS application server
      owner: IT Operations
      addresses: CVE-2026-69101
      evidence: Vulnerability allows SSRF and out-of-band file exfiltration
---

Datavane TIS version 5.0.0 contains an XML external entity (XXE) injection vulnerability arising from an insecurely configured DocumentBuilderFactory within the application's workflow editing functionality. Authenticated attackers can exploit this flaw by submitting a crafted XML payload containing external DTD references to the doEditWorkflow endpoint. Because the application processes these XML inputs with external entities and DTD loading enabled, it is susceptible to both server-side request forgery (SSRF) and out-of-band data exfiltration. Successful exploitation allows an attacker to force the server to initiate arbitrary outbound HTTP requests to attacker-controlled infrastructure and retrieve the contents of local system files. This exposes sensitive information readable by the TIS service user, including internal configuration files and Derby database credentials, which may be leveraged for further network penetration or lateral movement within the environment.

## Attack Chain

1. Attacker authenticates to the Datavane TIS application using valid user credentials.
2. Attacker crafts a malicious XML payload designed to trigger an external entity expansion, including a reference to a local system file (e.g., /etc/passwd or database configuration files).
3. Attacker directs the payload to the doEditWorkflow endpoint within the application interface.
4. The application receives the XML document as part of the taskScript parameter in an HTTP POST request.
5. The server-side XML parser (DocumentBuilderFactory) processes the DTD, resolving the external entity to the attacker-defined URI.
6. The application performs an outbound network request to the specified URI, facilitating SSRF or exfiltrating the contents of the referenced local file via the request body or response.
7. Attacker captures the exfiltrated data on their controlled listener, obtaining target configuration and database credentials.

## Impact

Successful exploitation of CVE-2026-69101 leads to full information disclosure of sensitive configuration data and database credentials stored on the application server. This impact is significant for organizations deploying Datavane TIS, as it grants attackers the ability to compromise the backend database and potentially gain further access to the internal network infrastructure. No specific number of victims has been confirmed, but the vulnerability affects all instances of Datavane TIS v5.0.0.

## Recommendation

* Update Datavane TIS to the latest patched version immediately upon release to remediate the insecure DocumentBuilderFactory configuration.
* Implement egress filtering on the application server to block unauthorized outbound network connections, effectively limiting the impact of potential SSRF and OOB exfiltration attempts.
* Monitor web server logs for HTTP POST requests to the 'doEditWorkflow' endpoint containing XML structures with 'DOCTYPE' or 'ENTITY' declarations.
