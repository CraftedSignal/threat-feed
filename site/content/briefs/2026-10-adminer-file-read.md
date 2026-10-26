---
brief_id: brief-2026-10-26-adminer-file-read
event_id: brief-2026-10-26-adminer-file-read
revision: 1
activity_at: "2026-10-26T21:06:03Z"
title: 'Adminer: Arbitrary file read via rogue MySQL server (CVE-2020-35572)'
slug: 2026-10-adminer-file-read
description: Adminer versions 4.7.8 and earlier are vulnerable to an arbitrary file read via a rogue MySQL server connection that facilitates the LOAD DATA LOCAL INFILE command.
date: "2026-10-26T21:06:03Z"
type: advisory
types:
  - advisory
severities:
  - low
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: B
  credibility: "2"
  rating: B2
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Check for Adminer presence in environment and apply recommended patches or access controls
cpes:
  - cpe:2.3:a:adminer:adminer:*:*:*:*:*:*:*:*
vendors:
  - Adminer
products:
  - Adminer (<= 4.7.8)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Adminer server driver allows arbitrary file read via rogue-MySQL LOAD DATA LOCAL.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1005
    technique_name: Data from Local System
    evidence: By leveraging the LOAD DATA LOCAL INFILE command during the MySQL session, the attacker can instruct the application to read and exfiltrate sensitive files.
    confidence_band: high
cves:
  - id: CVE-2020-35572
    cvss: 6.1
    epss: 0.02003
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2020-35572
  - https://sploitus.com/exploit?id=KS:EXPLOITS-MULTI-HTTP-ADMINER_CVE_2020_35572_FILEREAD
  - https://sploitus.com/exploit?id=KS:EXPLOITS-MULTI-HTTP-ADMINER_CVE_2020_35572_FILEREAD&utm_source=rss&utm_medium=rss
rules:
  - title: Detect Adminer Rogue MySQL Connection Attempt
    description: Detects potential CVE-2020-35572 exploitation where an Adminer instance submits an external database server in the authentication field.
    platform: sigma
    severity: medium
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
    - SOC
  immediate_actions:
    - action: Inventory all Adminer installations and update to a version > 4.7.8.
      owner: IT Operations
      due: 48h
      evidence: Adminer version 4.7.8 is explicitly identified as vulnerable.
    - action: Deploy webserver-level rules to detect unauthorized connections to Adminer from external sources.
      owner: SOC
      due: 24h
      evidence: Exploit requires communication between Adminer and a rogue database server.
  hunt_leads:
    - lead: Identify outbound network connections from web server processes to unknown or untrusted database endpoints.
      technique_id: T1071.001
      data_needed:
        - Netflow or Firewall logs
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The exploit forces the application to connect outbound to an attacker-controlled MySQL host.
  mitigation_plan:
    - priority: immediate
      action: Upgrade Adminer to patched version.
      owner: IT Operations
      addresses: CVE-2020-35572
      evidence: NVD advisory for CVE-2020-35572.
---

CVE-2020-35572 allows an unauthenticated attacker to perform arbitrary file reads on the server hosting Adminer. By forcing the Adminer application to connect to a rogue MySQL server controlled by the attacker, the application can be instructed to execute the 'LOAD DATA LOCAL INFILE' command, exfiltrating contents of arbitrary files from the target filesystem to the attacker's database. A functional proof-of-concept exploit module has been identified and linked to the Kittysploit framework.

## Attack Chain
1. Attacker initializes a rogue MySQL server accessible from the target Adminer host.
2. Attacker identifies the target Adminer instance (e.g., /adminer.php).
3. Attacker triggers a connection from the target Adminer instance to the rogue MySQL server by submitting the rogue server address in the 'auth[server]' field via a POST request.
4. Adminer performs a handshake with the rogue MySQL server.
5. Attacker observes the connection and obtains the SQL token required for subsequent administrative operations.
6. Attacker sends a POST request containing a malicious SQL query: 'LOAD DATA LOCAL INFILE "[path]" INTO TABLE [table]'.
7. Adminer reads the file from its local filesystem and transmits the content to the rogue MySQL server.
8. Attacker retrieves the exfiltrated data by querying the rogue MySQL database.

## Impact
Successful exploitation results in the unauthorized disclosure of sensitive files (e.g., /etc/passwd or configuration files) from the server hosting the vulnerable Adminer instance, potentially leading to full system compromise.

## Recommendation
- Patch Adminer to a version beyond 4.7.8 immediately.
- If patching is not possible, restrict access to the Adminer interface to trusted IP addresses using firewall rules or web server access control lists.
- Disable the 'LOAD DATA LOCAL' functionality in the MySQL client configuration on the server if not required.
- Monitor for unexpected outbound network connections initiated by the web server service account.
