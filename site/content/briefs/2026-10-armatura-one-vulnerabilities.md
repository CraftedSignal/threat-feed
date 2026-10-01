---
title: Critical Vulnerabilities in Armatura One Access Control Systems
slug: 2026-10-armatura-one-vulnerabilities
description: Multiple high-severity vulnerabilities in Armatura One, including an Apache ActiveMQ deserialization flaw, expose critical physical access-control infrastructure to remote code execution and credential compromise.
date: "2026-10-01T17:06:06Z"
type: advisory
types:
  - advisory
severities:
  - critical
cpes:
  - cpe:2.3:a:apache:activemq:*:*:*:*:*:*:*:*
  - cpe:2.3:a:apache:activemq_legacy_openwire_module:*:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:10.0:*:*:*:*:*:*:*
  - cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:e-series_santricity_unified_manager:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:e-series_santricity_web_services_proxy:-:*:*:*:*:*:*:*
  - cpe:2.3:a:netapp:santricity_storage_plugin:-:*:*:*:*:vcenter:*:*
tags:
  - critical-infrastructure
  - access-control
  - remote-code-execution
  - ics
vendors:
  - Armatura LLC
products:
  - Armatura One (<4.7.2)
  - Armatura One (USA) (<4.6.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: CVE-2023-46604 allows an unauthenticated network attacker to trigger deserialization of an arbitrary object graph.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059.003
    technique_name: 'Command and Scripting Interpreter: Windows Command Shell'
    evidence: This can result in arbitrary code execution with the highest level of privilege on the host operating system.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552.001
    technique_name: 'Credentials in Files: Configuration Files'
    evidence: Armatura One stores database and message-broker credentials in an install configuration file.
    confidence_band: high
cves:
  - id: CVE-2023-46604
    cvss: 10
    epss: 0.99891
references:
  - https://www.cisa.gov/news-events/ics-advisories/icsa-26-274-01
  - https://www.cve.org/CVERecord?id=CVE-2023-46604
  - https://www.cve.org/CVERecord?id=CVE-2026-94591
  - https://www.cve.org/CVERecord?id=CVE-2026-94592
  - https://www.cve.org/CVERecord?id=CVE-2026-94593
  - https://www.cve.org/CVERecord?id=CVE-2026-94594
action_plan:
  priority: immediate_escalation
  owners:
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch Armatura One to 4.7.2 or Armatura One (USA) to 4.6.1_USA.
      owner: IT Operations
      due: 24h
      evidence: Vendor fix provided in CISA ICSA-26-274-01.
  hunt_leads:
    - lead: Search for plaintext credentials in Armatura One log directories.
      technique_id: T1552.001
      data_needed:
        - File access logs
        - Log content analysis
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: 'CVE-2026-94593: Backup and restore routine records database connection commands in plain text.'
---

Armatura LLC's Armatura One access-control platform contains several critical vulnerabilities that expose systems to unauthorized access and full compromise. The most severe, CVE-2023-46604, arises from an embedded Apache ActiveMQ component that enables unauthenticated remote code execution (RCE) via the OpenWire protocol listener. Additional vulnerabilities, including CVE-2026-94591, CVE-2026-94592, and CVE-2026-94593, stem from insecure default configurations such as hard-coded cryptographic keys, hard-coded database superuser passwords, and the logging of sensitive database credentials in plain text. These issues collectively allow an attacker to bypass authentication, decrypt sensitive configuration data, and gain elevated privileges on the host server. The affected products include Armatura One versions prior to 4.7.2 and Armatura One (USA) versions prior to 4.6.1. These systems are used across energy, communications, and critical manufacturing sectors, making them a high-value target for disruption or physical security breach.

## Attack Chain

1. An attacker identifies an internet-exposed Armatura One server with the Apache ActiveMQ OpenWire listener active.
2. The attacker sends a crafted malicious object through the OpenWire protocol to exploit the CVE-2023-46604 deserialization flaw.
3. The server deserializes the object, resulting in arbitrary code execution with the highest level of privilege.
4. The attacker accesses the host filesystem to locate installation configuration files containing encrypted credentials.
5. Utilizing the hard-coded AES-128-CBC key recovered from the application binary (CVE-2026-94591), the attacker decrypts the stored configuration data.
6. The attacker leverages the recovered database superuser password (CVE-2026-94592) or credentials exposed in plaintext logs (CVE-2026-94593) to gain direct database access.
7. The attacker modifies access-control lists or system settings to gain persistent control over the facility's physical security systems.

## Impact

Successful exploitation allows unauthenticated attackers to achieve full host system compromise, including the execution of arbitrary code with administrative privileges. Impact includes unauthorized access to critical databases, loss of integrity in physical access control, and the potential for complete control over security systems in sensitive environments like critical manufacturing and energy sector facilities.

## Recommendation

1. Upgrade Armatura One to version 4.7.2 or later, or Armatura One (USA) to version 4.6.1_USA or later, as specified in the vendor remediation guidance.
2. Perform a security review of all Armatura One deployments to ensure default credentials have been rotated and sensitive log files are restricted from unauthorized access.
3. Restrict network access to the Apache ActiveMQ OpenWire port (default port 61616) to trusted management subnets to mitigate CVE-2023-46604 if patching is delayed.
4. Hunt for unauthorized access to Armatura One configuration files and log directories on host systems.
