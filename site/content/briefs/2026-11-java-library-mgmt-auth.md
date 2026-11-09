---
brief_id: brief-2026-11-09-java-library-mgmt-auth
event_id: brief-2026-11-09-java-library-mgmt-auth
revision: 1
activity_at: "2026-11-09T11:38:49Z"
title: 'Java Library Management System: Improper authorization vulnerability (CVE-2026-124621)'
slug: 2026-11-java-library-mgmt-auth
description: An improper authorization vulnerability in the Swing UI layer of Java Library Management System has been identified, allowing for potential remote exploitation.
date: "2026-11-09T11:38:49Z"
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
  - cpe:2.3:a:kongxin_github:java_library_management_system:*:*:*:*:*:*:*:*
vendors:
  - kongxin-github
products:
  - Java_Library_Management_System (<= 70a6eb6b96fe64575d8051f1a59055bfc5dc5885)
cves:
  - id: CVE-2026-124621
    cvss: 7.4
    kev_status: "false"
references:
  - https://nvd.nist.gov/vuln/detail/CVE-2026-124621
---

A vulnerability exists in kongxin-github Java_Library_Management_System (up to commit 70a6eb6b96fe64575d8051f1a59055bfc5dc5885). The vulnerability stems from improper authorization in the Swing UI Layer within src/view/MainInterface.java, specifically affecting the functions UpdateAdmin.deleteuser, UpdateAdmin.updateadmin, UpdateAdmin.updatepass, Book.addbook, Book.modifybook, Book.deletebook, Category.addcategory, Category.setcategory, and Landing.sureadmin. The vulnerability is capable of being exploited remotely. The exploit has been publicly disclosed. The project maintainers have been informed but have not provided a response.
