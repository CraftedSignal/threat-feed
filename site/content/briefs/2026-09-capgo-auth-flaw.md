---
title: Authorization Flaw in Capgo App Icon Update Path
slug: 2026-09-capgo-auth-flaw
description: An authorization vulnerability in the Capgo PUT /app/:id endpoint allows authenticated users to trick a privileged backend worker into overwriting restricted storage objects.
date: "2026-09-26T16:59:54Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:capgo:capgo.app:*:*:*:*:*:*:*:*
tags:
  - web-application
  - privilege-escalation
  - cloud
vendors:
  - Capgo
products:
  - capgo.app (all versions)
mitre_ttps:
  - tactic_id: TA0004
    tactic_name: Privilege Escalation
    technique_id: T1068
    technique_name: Exploitation for Privilege Escalation
    evidence: The background worker, executing with elevated service-role credentials, performs a re-upload of the referenced storage object, bypassing RLS policies.
    confidence_band: high
cves:
  - id: CVE-2026-100618
    cvss: 8.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-100618
action_plan:
  priority: elevated
  owners:
    - SOC
    - Detection Engineering
  immediate_actions:
    - action: Review API logs for abnormal usage of the icon update endpoint
      owner: SOC
      due: 24h
      evidence: PUT /app/:id endpoint accepts a user-controlled icon value without validation
  mitigation_plan:
    - priority: immediate
      action: Enforce strict namespace validation for image path inputs on the application server
      owner: IT Operations
      addresses: CVE-2026-100618
      evidence: Lack of validation allows user to specify arbitrary image paths
---

Capgo (capgo.app) is vulnerable to an authorization flaw within the app icon update mechanism. The PUT /app/:id endpoint fails to validate that the provided 'icon' value resides within the specific app's image namespace. By submitting a path pointing to an out-of-scope storage object, an authenticated user with limited write access can influence the application's backend worker. 

When the 'icon' field is updated, it triggers the 'on_app_update' event. A background worker, executing with elevated service-role credentials (supabaseAdmin()), subsequently processes this record by calling 'cleanStoredImageMetadata()'. This function performs a download and re-upload (upsert) operation on the attacker-supplied object path. Because the worker operates with administrative privileges, it bypasses Supabase Row Level Security (RLS) constraints, effectively allowing an attacker to overwrite sensitive files, such as organization logos, to which they would otherwise lack read or write permissions. This vulnerability affects all current versions of the service.

## Impact

An attacker exploiting this vulnerability can perform unauthorized file overwrites within the Supabase storage backend. This can lead to the defacement of organization-level assets or potential operational disruption by replacing legitimate system images with malicious or arbitrary content, bypassing standard access controls.

## Recommendation

* Monitor API access logs for PUT requests to the '/app/:id' endpoint involving suspicious or unexpected file paths in the 'icon' parameter.
* Review Supabase storage bucket permissions and audit the 'on_app_update' trigger function for any unauthorized modifications.
* Implement additional input validation on the application layer to enforce strict namespace checks for user-provided image paths before they reach the backend processing trigger.
* Monitor for unauthorized upsert operations within sensitive storage directories where organization logos or administrative assets are stored.
