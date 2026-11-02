---
brief_id: brief-2026-11-02-cloudclassroom-php-vuln
event_id: brief-2026-11-02-cloudclassroom-php-vuln
revision: 1
activity_at: "2026-11-02T07:17:12Z"
title: 'mathurvishal CloudClassroom-PHP-Project: Execution After Redirect (CVE-2026-120341)'
slug: 2026-11-cloudclassroom-php-vuln
description: A remote execution after redirect vulnerability in the studentdetails.php file of the CloudClassroom-PHP-Project application allows for remote exploitation via publicly available exploit code.
date: "2026-11-02T07:17:12Z"
type: advisory
types:
  - advisory
severities:
  - high
exploitation_evidence:
  status: unknown
source_assessment:
  reliability: A
  credibility: "2"
  rating: A2
  likelihood: roughly even chance
cpes:
  - cpe:2.3:a:mathurvishal:cloudclassroom_php_project:*:*:*:*:*:*:*:*
vendors:
  - mathurvishal
products:
  - CloudClassroom-PHP-Project
mitre_ttps:
  - tactic_id: TA0001
    tactic_name: Initial Access
    technique_id: T1190
    technique_name: Exploit Public-Facing Application
    evidence: The manipulation leads to execution after redirect. Remote exploitation of the attack is possible.
    confidence_band: high
cves:
  - id: CVE-2026-120341
    cvss: 7.3
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-120341
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Inventory all deployments of mathurvishal CloudClassroom-PHP-Project.
      owner: SOC
      due: 24h
      evidence: Vulnerability affects this specific product.
  hunt_leads:
    - lead: Search web access logs for requests to /studentdetails.php that are followed by unexpected redirects or subsequent abnormal application behavior.
      technique_id: T1190
      data_needed:
        - Web server access logs (cs-uri-stem, cs-method, sc-status, sc-location)
      priority: high
      confidence: medium
      disposition: hunt_now
      evidence: The vulnerability manifests in studentdetails.php and involves execution after redirect.
  mitigation_plan:
    - priority: immediate
      action: Restrict network access to studentdetails.php via WAF or web server configuration until a security assessment or update is available.
      owner: IT Operations
      addresses: CVE-2026-120341
      evidence: Remote exploitation of the attack is possible.
---

A security vulnerability exists in the studentdetails.php file of the CloudClassroom-PHP-Project application. The flaw enables remote execution after redirect. Public exploit code is available for this vulnerability. As the project follows a rolling release model, no specific affected or fixed version information is currently available. The vendor has not responded to disclosure attempts.

## Impact
The vulnerability allows for remote exploitation, potentially leading to unauthorized execution within the web application context.

## Recommendation
- Identify all instances of the CloudClassroom-PHP-Project within the enterprise environment.
- Implement access control restrictions to limit public access to the studentdetails.php endpoint.
- Monitor web server access logs for anomalous requests to studentdetails.php that precede redirected responses or suspicious subsequent requests.
- Evaluate the necessity of the application given the lack of vendor response and absence of formal patch management in a rolling release model.
