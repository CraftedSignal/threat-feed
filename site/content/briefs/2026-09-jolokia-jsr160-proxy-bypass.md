---
title: Jolokia JSR-160 Proxy JNDI Injection Vulnerability
slug: 2026-09-jolokia-jsr160-proxy-bypass
description: Jolokia JSR-160 proxy contains an insufficient validation flaw, identified as CVE-2026-84218, which allows attackers to bypass denylists and trigger JNDI lookups leading to SSRF or remote code execution.
date: "2026-09-01T15:07:16Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:jolokia:jolokia:*:*:*:*:*:*:*:*
  - cpe:2.3:a:jolokia:webarchive_agent:1.3.7:*:*:*:*:*:*:*
tags:
  - vulnerability
  - java
  - jmx
  - jndi
  - ssrf
vendors:
  - Jolokia
products:
  - Jolokia
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The proxy accepts a target.url value from a Jolokia POST request and passes it to JMXServiceURL and JMXConnectorFactory for establishing the remote JMX connection.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1203
    technique_name: Exploitation for Client Execution
    evidence: This can result in server-side request forgery (SSRF), forwarding of supplied JMX credentials to the remote endpoint, and potentially remote code execution depending on the classes and configuration available in the target JVM.
    confidence_band: high
cves:
  - id: CVE-2026-84218
    cvss: 8.1
  - id: CVE-2018-1000130
    cvss: 8.1
    epss: 0.72696
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-84218
action_plan:
  priority: elevated
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Inventory all servers running Jolokia agents to assess exposure
      owner: IT Operations
      due: 24h
      evidence: CVE-2026-84218 vulnerability report
  hunt_leads:
    - lead: Search web logs for POST requests to Jolokia endpoints containing ldaps or jndi strings in target.url
      technique_id: T1190
      data_needed:
        - webserver access logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Vulnerability allows bypassing denylist using ldaps or modified LDAP URLs
  mitigation_plan:
    - priority: immediate
      action: Disable Jolokia JSR-160 proxy functionality if it is not strictly necessary for operations
      owner: IT Operations
      addresses: CVE-2026-84218
      evidence: Vulnerability exists within JSR-160 proxy functionality
---

CVE-2026-84218 describes a security vulnerability in the Jolokia JSR-160 proxy functionality. The flaw stems from insufficient validation of client-controlled JMX service URLs, which effectively bypasses the security denylist originally established to address CVE-2018-1000130. By sending a crafted Jolokia POST request, an attacker can manipulate the `target.url` parameter. Because the existing denylist logic only explicitly rejects standard `service:jmx:rmi:///jndi/ldap:.*` patterns, it fails to account for alternative valid JMX service URL formats, such as `ldaps://` schemes or LDAP URLs containing a non-empty JMX host component.

When processed, these malformed URLs are accepted as valid `JMXServiceURL` objects, prompting the Jolokia agent JVM to perform an unintended JNDI lookup against an attacker-controlled endpoint. The impact of this behavior ranges from server-side request forgery (SSRF) and the exfiltration of JMX credentials to potential remote code execution (RCE), depending on the specific classes available within the target JVM classpath. This vulnerability is highly relevant for environments deploying Jolokia as an agent for JMX management.

## Impact

Successful exploitation allows unauthenticated attackers to perform SSRF and credential exfiltration via the Jolokia agent. Depending on the target's JVM configuration and available gadget chains, attackers may achieve remote code execution. This poses a significant risk to enterprise Java applications that utilize Jolokia for remote management, potentially leading to full compromise of the application server.

## Recommendation

Prioritize the identification of all Jolokia instances within the network footprint. Monitor web server logs for POST requests containing `target.url` parameters. Audit the Jolokia configuration to ensure that the JSR-160 proxy is disabled if not required for business operations. Apply patches provided by the Jolokia project immediately upon release to address the validation logic flaw.
