---
title: Arbitrary Content Deletion in Photo Reviews for WooCommerce Plugin
slug: 2026-10-photo-reviews-wc-vuln
description: An unauthenticated arbitrary content deletion vulnerability in the Photo Reviews for WooCommerce plugin (CVE-2026-101923) allows attackers to delete arbitrary site posts, pages, or media by injecting malicious IDs into review metadata.
date: "2026-10-03T06:53:48Z"
type: advisory
types:
  - advisory
severities:
  - high
cpes:
  - cpe:2.3:a:wp_photo_reviews_project:photo_reviews_for_woocommerce:*:*:*:*:*:wordpress:*:*
vendors:
  - WordPress
products:
  - Photo Reviews for WooCommerce (<= 1.2.30)
mitre_ttps:
  - tactic_id: TA0040
    tactic_name: Impact
    technique_id: T1485
    technique_name: Data Destruction
    evidence: This makes it possible for unauthenticated attackers to permanently delete arbitrary posts, pages, products, or media attachments on the site.
    confidence_band: high
cves:
  - id: CVE-2026-101923
    cvss: 8.1
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-101923
action_plan:
  priority: elevated
  owners:
    - IT Operations
    - Security Team
  immediate_actions:
    - action: Upgrade Photo Reviews for WooCommerce to a version beyond 1.2.30
      owner: IT Operations
      due: 24h
      evidence: Source documentation identifies versions <= 1.2.30 as vulnerable
  mitigation_plan:
    - priority: immediate
      action: Upgrade plugin to latest patched version
      owner: IT Operations
      addresses: CVE-2026-101923
      evidence: Source identifies vulnerability in versions <= 1.2.30
---

The Photo Reviews for WooCommerce plugin for WordPress, in versions 1.2.30 and below, contains a critical security flaw that allows for unauthorized content deletion. The vulnerability stems from the plugin's failure to validate the wcpr_image_upload_id parameter during public review submissions. An unauthenticated attacker can submit a review containing an arbitrary post ID, which the plugin stores in the review's comment metadata.

The plugin's delete_reviews_image() handler later processes this metadata by calling wp_delete_post() on the stored IDs. Consequently, when an administrator deletes the malicious review, or when the wp_scheduled_delete cron job purges the comment trash, the system unknowingly deletes the site content corresponding to the injected IDs. This impact includes the permanent loss of products, posts, pages, and media attachments. The vulnerability was disclosed via the NVD, and users are advised to upgrade to a version that addresses the lack of ownership verification on submitted image metadata IDs.

## Impact

Successful exploitation leads to the permanent, unauthorized deletion of arbitrary site data, including essential WooCommerce product pages, blog posts, media attachments, and administrative pages. If widely exploited, this vulnerability could cause massive site data loss, significant service disruption, and potential financial impact for e-commerce operators relying on the affected WooCommerce installation.

## Recommendation

Prioritized actions for administrators:
- Immediately update the "Photo Reviews for WooCommerce" plugin to the latest version (above 1.2.30) where verification of metadata IDs has been implemented.
- Review database or system logs for suspicious review submissions containing unconventional or unexpected ID values in the wcpr_image_upload_id parameter.
- Disable the "Photo Reviews for WooCommerce" plugin until a patch is applied if the site cannot be updated immediately.
