---
brief_id: brief-2026-10-28-n8n-odata-injection
event_id: brief-2026-10-28-n8n-odata-injection
revision: 1
activity_at: "2026-10-28T20:38:14Z"
title: 'n8n: OData $filter injection vulnerability (CVE-2026-118641)'
slug: 2026-10-n8n-odata-injection
description: n8n workflow nodes for Microsoft Outlook and SharePoint contain an OData $filter injection vulnerability allowing unauthorized data access and modification.
date: "2026-10-28T20:38:14Z"
lastmod: "2026-10-28T20:38:57Z"
type: advisory
claim_state: <nil>
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "1"
  rating: A1
  likelihood: likely
qa_status:
  verdict: pass
  validation_status: Source verified.
cpes:
  - cpe:2.3:a:n8n:n8n:*:*:*:*:*:*:*:*
tags:
  - injection
  - n8n
  - cve-2026-118641
  - authorization-bypass
  - cve-2026-118642
  - vulnerability
  - credential-access
  - cloud
  - privilege-escalation
  - cve-2026-118649
  - web-vulnerability
  - ssrf
  - exfiltration
vendors:
  - n8n GmbH
  - n8n
products:
  - n8n (< 1.123.85)
  - n8n (2.x < 2.43.5)
  - n8n (2.44.x < 2.44.1)
  - n8n (< 1.123.85, 2.43.5, 2.44.1)
  - n8n (< 2.43.5, 2.44.x < 2.44.1)
  - n8n (< 1.123.83, < 2.41.4, < 2.42.1)
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: Attackers who supply untrusted input to such workflows can inject single quotes to dump the bound mailboxs entire contact list or redirect SharePoint writes onto unintended list items within the stored credentials scope.
    confidence_band: high
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1078
    technique_name: Valid Accounts
    evidence: n8n before 1.123.85, 2.43.5, and 2.44.1 contains an authorization bypass vulnerability that allows authenticated members to use inaccessible credentials
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1048
    technique_name: Exfiltration Over Alternative Protocol
    evidence: Attackers knowing a credential id can run Execute Workflow nodes in inline JSON mode that skip the permission check and send decrypted credentials to attacker-controlled servers.
    confidence_band: high
  - tactic_id: TA0006
    tactic_name: Credential Access
    technique_id: T1552
    technique_name: Unsecured Credentials
    subtechnique_id: T1552.001
    subtechnique_name: Credentials In Files
    evidence: Users who can view a workflow's executions but cannot read the credential can recover Git passwords or tokens, MongoDB database passwords, or Google access tokens from that data.
    confidence_band: high
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: An authenticated member who can create and run workflows can list, read, modify, and delete Data Table rows in all projects of the instance.
    confidence_band: high
  - tactic_id: TA0010
    tactic_name: Exfiltration
    technique_id: T1530
    technique_name: Data from Cloud Storage
    evidence: Attackers who know the webhook URL can name a file to download, causing the node to send the workspace access token to an attacker host and return the response.
    confidence_band: high
cves:
  - id: CVE-2026-118641
    cvss: 7.5
    kev_status: "false"
  - id: CVE-2026-118642
    cvss: 7.1
    kev_status: "false"
  - id: CVE-2026-118643
    cvss: 8.2
    kev_status: "false"
  - id: CVE-2026-118645
    cvss: 8.7
    kev_status: "false"
  - id: CVE-2026-118649
    cvss: 8.3
    kev_status: "false"
  - id: CVE-2026-118679
    cvss: 7.5
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118641
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118642
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118643
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118645
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118649
  - https://nvd.nist.gov/vuln/detail/CVE-2026-118679
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - SOC
  immediate_actions:
    - action: Patch n8n instances to versions 1.123.85, 2.43.5, 2.44.1 or later.
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-118641 patch availability.
    - action: Patch n8n instances to versions >= 1.123.85, 2.43.5, or 2.44.1
      owner: IT Operations
      due: 48h
      evidence: n8n before 1.123.85, 2.43.5, and 2.44.1 contains an authorization bypass vulnerability
    - action: 'Upgrade n8n instances to the specified fixed versions: 1.123.85, 2.43.5, or 2.44.1.'
      owner: IT Operations
      due: 48h
      evidence: CVE-2026-118643 remediation requirements.
    - action: Upgrade n8n instances to 2.43.5 or 2.44.1 to patch CVE-2026-118649.
      owner: IT Operations
      due: 48h
      evidence: n8n before 2.43.5 and 2.44.x before 2.44.1 accepts a client-supplied workflow ID
    - action: Upgrade n8n to version 1.123.83, 2.41.4, or 2.42.1
      owner: IT Operations
      due: 24h
      evidence: Vulnerability addressed in specified versions
  hunt_leads:
    - lead: Identify n8n workflows utilizing Microsoft Outlook contact lookup or SharePoint v1 item update nodes that accept external user input.
      technique_id: T1190
      data_needed:
        - n8n workflow configurations (JSON/YAML exported workflows)
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The vulnerability is triggered via untrusted input to specific node parameters.
    - lead: Identify unauthorized access to sensitive credentials via Execute Workflow node modifications
      technique_id: T1078
      data_needed:
        - n8n application logs
        - Audit logs showing node configuration changes
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: Attackers knowing a credential id can run Execute Workflow nodes in inline JSON mode that skip the permission check
    - lead: Search n8n internal execution logs for error messages containing common credential patterns associated with Git, MongoDB, or Google Cloud nodes.
      technique_id: T1552.001
      data_needed:
        - n8n execution log export
        - Workflow error history
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: Execution error data stores credential secrets in the affected nodes.
    - lead: Identify authenticated users submitting API requests with workflow IDs containing "__proto__" or similar prototype pollution patterns.
      technique_id: T1068
      data_needed:
        - n8n application logs
        - web server access logs
      priority: medium
      confidence: medium
      disposition: hunt_now
      evidence: a crafted ID such as __proto__ makes the Data Table project check match every project
    - lead: Identify outbound HTTP requests from n8n instances to non-Slack domains
      technique_id: T1530
      data_needed:
        - Application egress logs / proxy logs
      priority: high
      confidence: high
      disposition: hunt_now
      evidence: The node transmits Slack workspace access tokens to an attacker host.
  mitigation_plan:
    - priority: immediate
      action: Upgrade n8n to 1.123.85 or later
      owner: IT Operations
      addresses: CVE-2026-118641
      evidence: NVD advisory for CVE-2026-118641.
    - priority: immediate
      action: Apply security patches for CVE-2026-118642
      owner: IT Operations
      addresses: CVE-2026-118642
      evidence: n8n before 1.123.85, 2.43.5, and 2.44.1 contains an authorization bypass vulnerability
    - priority: immediate
      action: Restrict access to workflow execution history for non-privileged users.
      owner: IT Operations
      addresses: CVE-2026-118643
      evidence: Unauthorized users with view access to workflow executions can recover credentials.
    - priority: immediate
      action: Upgrade n8n to 2.43.5 or later
      owner: IT Operations
      addresses: CVE-2026-118649
      evidence: n8n before 2.43.5 and 2.44.x before 2.44.1
    - priority: immediate
      action: Configure Slack signing secrets for all webhooks
      owner: IT Operations
      addresses: CVE-2026-118679
      evidence: Vulnerability allows bypass when no signing secret is set
updates:
  - at: "2026-10-28T20:38:22Z"
    level: L2
    summary: added coverage for n8n (< 1.123.85, 2.43.5, 2.44.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118642
  - at: "2026-10-28T20:38:26Z"
    level: L2
    summary: added coverage for n8n (< 1.123.85) +2 products
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118643
  - at: "2026-10-28T20:38:35Z"
    level: L2
    summary: added CVE-2026-118645
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118645
  - at: "2026-10-28T20:38:50Z"
    level: L2
    summary: added coverage for n8n (< 2.43.5, 2.44.x < 2.44.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118649
  - at: "2026-10-28T20:38:57Z"
    level: L2
    summary: added coverage for n8n (< 1.123.83, < 2.41.4, < 2.42.1)
    sources:
      - nvd
    source_urls:
      - https://nvd.nist.gov/vuln/detail/CVE-2026-118679
---

CVE-2026-118641 is an OData $filter injection vulnerability in n8n affecting the Microsoft Outlook contact lookup node and the Microsoft SharePoint v1 item update node. The nodes fail to escape expression-bindable parameters when constructing $filter strings, enabling attackers to inject single quotes. Successful exploitation allows for the unauthorized retrieval of contact lists from a mailbox or the manipulation of write operations to target unintended SharePoint list items within the scope of the configured credentials.

## Impact

An attacker can perform unauthorized exfiltration of mailbox contacts or manipulate SharePoint item updates. The scope of impact is limited to the permissions of the credentials configured within the n8n workflow.

## Recommendation

Update n8n to the patched versions immediately. The fixed versions are 1.123.85, 2.43.5, and 2.44.1. For environments where patching must be deferred, audit active n8n workflows that utilize the Microsoft Outlook contact lookup or Microsoft SharePoint v1 item update nodes to ensure inputs are not derived from untrusted user-controllable sources.
