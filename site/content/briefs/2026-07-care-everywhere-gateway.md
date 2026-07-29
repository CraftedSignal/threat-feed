---
title: Hard-coded Credentials in Care Everywhere Gateway WildFly Management Interface
slug: 2026-07-care-everywhere-gateway
description: An unauthenticated remote code execution vulnerability exists in Care Everywhere Gateway 14.3.10 due to hard-coded credentials within the bundled WildFly 8.2.0.Final management interface.
date: "2026-07-29T18:18:23Z"
type: advisory
types:
  - advisory
severities:
  - critical
vendors:
  - Care Everywhere
  - Red Hat
products:
  - Care Everywhere Gateway (14.3.10)
  - WildFly (8.2.0.Final)
affected_os:
  - Windows
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: An attacker can access the management console on port 20990 using these default credentials to deploy malicious WAR files, resulting in remote code execution.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: Attacker can ... deploy a malicious Web Application Archive file through the Deployments interface to achieve remote code execution.
    confidence_band: high
cves:
  - id: CVE-2026-41939
    cvss: 9.8
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-41939
---

Care Everywhere Gateway version 14.3.10 utilizes a legacy version of the WildFly application server (8.2.0.Final) which contains hard-coded management credentials. This vulnerability allows remote, unauthenticated attackers to access the WildFly management interface, which is typically exposed on TCP port 20990. Once authenticated using the known default credentials, an attacker can leverage the application's deployment functionality to upload a malicious Web Application Archive (WAR) file. Successful execution of this file results in remote code execution (RCE) running with the privileges of the underlying Windows service account. This product reached end-of-life (EOL) in 2017, and no patches are expected for version 14.3.10, necessitating immediate network-level isolation or decommissioning of affected instances.

## Attack Chain

1. Attacker performs network reconnaissance to identify instances of Care Everywhere Gateway exposing port 20990.
2. Attacker initiates an HTTP connection to the WildFly management interface on port 20990.
3. Attacker authenticates to the management interface using hard-coded default credentials.
4. Attacker navigates to the 'Deployments' management interface within the WildFly console.
5. Attacker uploads a crafted, malicious .war file containing web shell or malware code.
6. Attacker triggers the deployment of the uploaded .war file via the management console.
7. The WildFly service extracts and executes the malicious application within the web server context.
8. Attacker achieves remote code execution as the Windows system account running the service.

## Impact

Successful exploitation grants an attacker full administrative control over the affected Windows host running the Care Everywhere Gateway. Because the gateway often resides in sensitive infrastructure, this facilitates initial access into the internal network, potential exfiltration of sensitive medical or operational data, and lateral movement. Given the EOL status of the product, all identified instances represent a permanent high-risk security debt to the organization.

## Recommendation

* Immediately isolate all Care Everywhere Gateway 14.3.10 instances by blocking ingress and egress traffic to port 20990 at the perimeter firewall.
* Audit network logs for any inbound traffic to port 20990 originating from unauthorized subnets or external IP addresses.
* Plan for the immediate decommissioning of EOL software instances, as no security patches are available for CVE-2026-41939.
* Search for unauthorized .war files placed within the WildFly deployment directories on the host operating system.
