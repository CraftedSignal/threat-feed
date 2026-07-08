---
title: 'CVE-2026-56250: Capgo R2 Bundle Object Deletion via Mutable r2_path'
slug: 2026-07-capgo-r2-path-dos
description: A critical vulnerability, CVE-2026-56250, in Capgo before version 12.128.2 allows an authenticated attacker with upload-scoped API keys to manipulate the app_versions.r2_path field via PostgREST, leading to arbitrary R2 bundle object deletion and denial of service.
date: "2026-07-08T14:22:30Z"
type: advisory
types:
  - advisory
severities:
  - medium
tags:
  - vulnerability
  - denial-of-service
  - cloud
  - web-application
vendors:
  - Capgo
products:
  - Capgo < 12.128.2
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: trigger the on_version_update cleanup function to delete the victim R2 object
    confidence_band: high
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1531
    technique_name: Account Access Removal
    evidence: causing denial of service and bundle availability disruption
    confidence_band: high
cves:
  - id: CVE-2026-56250
    cvss: 7.5
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-56250
  - https://github.com/Cap-go/capgo/security/advisories/GHSA-pw8p-5jg6-cxj3
  - https://www.vulncheck.com/advisories/capgo-arbitrary-r2-object-deletion-via-mutable-r2-path-in-app-versions
iocs:
  - type: url
    value: https://github.com/Cap-go/capgo/security/advisories/GHSA-pw8p-5jg6-cxj3
  - type: url
    value: https://www.vulncheck.com/advisories/capgo-arbitrary-r2-object-deletion-via-mutable-r2-path-in-app-versions
ioc_counts:
  url: 2
---

Capgo, an open-source tool for managing Capacitor applications, is affected by CVE-2026-56250, a high-severity vulnerability present in versions prior to 12.128.2. This flaw enables an attacker possessing an upload-scoped API key to modify the `app_versions.r2_path` field through the PostgREST interface. By exploiting this, the attacker can redirect the path of an application version they control to point to arbitrary R2 bundle objects belonging to a victim. Subsequently, by initiating a "soft-delete" operation on their modified version, the attacker can trigger an internal `on_version_update` cleanup function that then inadvertently deletes the victim's targeted R2 object. This results in a denial of service and significant disruption to bundle availability for applications managed by the vulnerable Capgo instance, severely impacting operational integrity.

## Attack Chain

1. Attacker obtains a valid upload-scoped API key for a Capgo instance, which provides legitimate access to interact with application versions.
2. Attacker identifies a target application version within Capgo that they control and a victim's critical R2 bundle object they wish to delete.
3. Attacker uses the upload-scoped API key to make a PATCH request via PostgREST, targeting the `app_versions.r2_path` field of their controlled application version.
4. The `r2_path` field is modified to point from the attacker's own R2 bundle object to the specific victim R2 bundle object, effectively retargeting it.
5. Attacker initiates an action (e.g., publishing a new version that makes the previous one obsolete) that leads to a "soft-delete" of their now-maliciously-configured application version.
6. Capgo's backend executes the `on_version_update` cleanup function, which follows the attacker-modified `r2_path`.
7. The cleanup function then erroneously attempts to "clean up" the R2 object at the retargeted path, resulting in the deletion of the victim's legitimate R2 bundle object.
8. Victim's applications that rely on the deleted R2 bundle object experience service disruption and denial of service due to unavailability of necessary resources.

## Impact

The observed impact of CVE-2026-56250 exploitation is a direct denial of service (DoS) affecting applications and services managed by Capgo deployments. Attackers can leverage this vulnerability to arbitrarily delete crucial R2 bundle objects, rendering legitimate applications inoperable or unavailable. This can lead to severe operational disruptions, loss of data integrity (due to missing bundles), and potential financial and reputational damage for affected organizations. The vulnerability specifically targets the availability of application bundles, which are fundamental to the functionality of Capgo-managed applications, affecting any organization using vulnerable Capgo versions.

## Recommendation

* Immediately update Capgo to version 12.128.2 or newer to remediate CVE-2026-56250.
* Review and enforce strict access control policies for all Capgo API keys, ensuring that upload-scoped keys lack permissions to modify sensitive configuration paths like `app_versions.r2_path`.
* Monitor Capgo application logs and PostgREST access logs for any unauthorized or unusual PATCH requests to the `app_versions.r2_path` field or unexpected deletion events in R2 storage.
