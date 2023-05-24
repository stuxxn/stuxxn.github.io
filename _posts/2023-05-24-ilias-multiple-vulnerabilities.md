---
layout: post_collection
date:   2023-05-24
categories: [advisory]
advisory_tag: ilias_multi_2023

title:  "[Advisory - ILIAS] Multiple vulnerabilities (LFI, Auth bypass, RCE)"
advisory:
  product: ILIAS eLearning platform
  homepage: https://www.ilias.de/en/about-ilias/  
  vulnerable_version: "ILIAS <= 7.20, <= 8.1"
  fixed_version: "ILIAS 7.21, 8.2"
  found: 2023-02-02
---

# Timeline
* 2023-04-26: Contacted vendor (rob.falkenstein@rz.uni-freiburg.de), Asking for GPG key
* 2023-04-28: Sent details about vulnerabilites to vendor
* 2023-05-05: Release of version 7.21 (fixes CVE-2023-32779, CVE-2023-31467)
* 2023-05-08: Vendor acknowledged vulnerabilites and is working on a fix
* 2023-05-17: Release of version 8.2 (fixes CVE-2023-32779, CVE-2023-31467, CVE-2023-32778)
* 2023-05-19: Planing the disclosure date of the advisories of CVE-2023-32779, CVE-2023-31467 with the vendor - 2023-05-24
* 2023-05-24: Public release of advisory for CVE-2023-32779, CVE-2023-31467