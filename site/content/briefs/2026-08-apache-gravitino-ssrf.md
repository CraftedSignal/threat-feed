---
title: Apache Gravitino Authenticated Server-Side Request Forgery
slug: 2026-08-apache-gravitino-ssrf
description: Apache Gravitino versions 1.0.0 through 1.2.1 contain an authenticated SSRF vulnerability (CVE-2026-49876) allowing attackers to perform internal network reconnaissance or access metadata services.
date: "2026-08-11T15:06:57Z"
type: advisory
types:
  - advisory
severities:
  - low
cpes:
  - cpe:2.3:a:apache:gravitino:*:*:*:*:*:*:*:*
vendors:
  - Apache
products:
  - Gravitino
affected_os:
  - Ubuntu 22.04 LTS
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: A Server-Side Request Forgery (SSRF) vulnerability exists in Apache Gravitino versions 1.0.0 through 1.2.1.
    confidence_band: high
  - tactic_id: TA0002
    tactic_name: Execution
    technique_id: T1059
    technique_name: Command and Scripting Interpreter
    evidence: The fetchFileFromUri() method in JobManager.java processes URIs from job template fields (executable, scripts, jars, files, archives).
    confidence_band: high
cves:
  - id: CVE-2026-49876
    cvss: 6.5
    epss: 0.00402
references:
  - https://www.exploit-db.com/exploits/52641
  - https://nvd.nist.gov/vuln/detail/CVE-2026-49876
rules:
  - title: Detect CVE-2026-49876 Exploitation - Gravitino Job Template SSRF
    description: Detects exploitation of CVE-2026-49876 by monitoring for POST requests to the Gravitino job template API containing potential SSRF target URI patterns in the job template body.
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
    - SOC
    - IT Operations
  immediate_actions:
    - action: Patch all instances of Apache Gravitino to version 1.3.0 or later
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-49876 advisory
  enrichment_needed:
    - item: CVE-2026-49876
      owner: CTI
      reason: Confirm availability of vendor fix
      evidence: CVE database
  hunt_leads:
    - lead: Search logs for unauthorized attempts to access 169.254.169.254 from web servers
      technique_id: T1190
      data_needed:
        - webserver_logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Exploit PoC code targeting cloud metadata
  mitigation_plan:
    - priority: immediate
      action: Egress filtering for Gravitino server
      owner: Network Security
      addresses: CVE-2026-49876
      evidence: Vulnerability allows arbitrary URI fetching
  gaps:
    - None
---

Apache Gravitino versions 1.0.0 through 1.2.1 are susceptible to a Server-Side Request Forgery (SSRF) vulnerability identified as CVE-2026-49876. The vulnerability resides within the `fetchFileFromUri()` method in `JobManager.java`, which processes job template fields such as executable scripts, jars, and archives. The application fails to validate the destination URI provided by users, permitting the use of http, https, and ftp schemes. By registering a malicious job template, an authenticated attacker can force the server to fetch content from internal network resources or cloud metadata services. The downloaded content is subsequently written to the server's staging directory. This impact is significant for environments leveraging Gravitino in cloud deployments, where the application may be used to exfiltrate cloud instance identity tokens via the metadata service.

## Attack Chain

1. Attacker authenticates to the Apache Gravitino REST API using valid user credentials.
2. Attacker interacts with the `/api/metalakes/{metalake}/jobs/templates` endpoint to register a new job template.
3. Attacker specifies a crafted URI in the `executable` field of the job template, pointing to an internal resource (e.g., `http://169.254.169.254/latest/meta-data/`).
4. Attacker triggers the job execution via the `/api/metalakes/{metalake}/jobs/runs` endpoint.
5. The application's `fetchFileFromUri()` method processes the job template and initiates an outbound request to the attacker-supplied URI.
6. The server fetches the remote resource and saves it to the local staging directory via `FileUtils.copyURLToFile()`.
7. Attacker retrieves the content from the staging directory or observes interactions via an OOB callback server if blind SSRF techniques are employed.

## Impact

Successful exploitation allows an authenticated attacker to perform unauthorized internal reconnaissance, access sensitive configuration files, or exfiltrate cloud environment metadata (such as IAM role credentials). The scope affects all Gravitino instances between versions 1.0.0 and 1.2.1, with Ubuntu 22.04 environments explicitly confirmed as a target platform.

## Recommendation

* Upgrade Apache Gravitino to the latest version that includes the patch for CVE-2026-49876.
* Restrict access to the Gravitino REST API to trusted users and IP ranges.
* Enable egress filtering on the application server hosting Gravitino to prevent unauthorized connections to sensitive internal subnets and cloud metadata endpoints (e.g., 169.254.169.254).
* Deploy the provided Sigma rule to monitor for suspicious job template registration patterns via web server logs.
