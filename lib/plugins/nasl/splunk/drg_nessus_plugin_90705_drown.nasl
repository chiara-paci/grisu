# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.300002");
  script_version("2023-08-17T14:10:00+0000");
  script_tag(name:"cvss_base", value:"9.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-17 14:10:00 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Splunk Enterprise < 5.0.15 / 6.0.11 / 6.1.10 / 6.2.9 / 6.3.3.4 or Splunk Light < 6.2.9 / 6.3.3.4 Multiple Vulnerabilities (DROWN)");

  script_cve_id("CVE-2015-7995", "CVE-2016-0702", "CVE-2016-0705", "CVE-2016-0797", "CVE-2016-0798", "CVE-2016-0799", "CVE-2016-0800");

  script_tag(name:"summary", value:"The remote web server is running an application that is affected by multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute remote code on the affected application/system and/or
  cause a cause a denial of service.");

  script_tag(name:"insight", value:"According to its version number, the instance of Splunk hosted on the remote web server is Enterprise 5.0.x prior to 5.0.15, 6.0.x prior to 6.0.11, 6.1.x prior to 6.1.10, 6.2.x prior to 6.2.9, 6.3.x prior to 6.3.3.4, Light 6.2.x prior to 6.2.9, or Light 6.3.x prior to 6.3.3.4.
It is, therefore, affected by the following vulnerabilities :

- A type confusion error exists in the bundled version of libxslt in the xsltStylePreCompute() function due to improper handling of invalid values. A context-dependent attacker can exploit this, via crafted XML files, to cause a denial of service condition. (CVE-2015-7995)

- A key disclosure vulnerability exists in the bundled version of OpenSSL due to improper handling of cache-bank conflicts on the Intel Sandy-bridge microarchitecture. An attacker can exploit this to gain access to RSA key information. (CVE-2016-0702)

- A double-free error exists in the bundled version of OpenSSL due to improper validation of user-supplied input when parsing malformed DSA private keys. A remote attacker can exploit this to corrupt memory, resulting in a denial of service condition or the execution of arbitrary code. (CVE-2016-0705)

- A NULL pointer dereference flaw exists in the bundled version of OpenSSL in the BN_hex2bn() and BN_dec2bn() functions. A remote attacker can exploit this to trigger a heap corruption, resulting in the execution of arbitrary code. (CVE-2016-0797)

- A denial of service vulnerability exists in the bundled version of OpenSSL due to improper handling of invalid usernames. A remote attacker can exploit this, via a specially crafted username, to leak 300 bytes of memory per connection, exhausting available memory resources.
(CVE-2016-0798)

- Multiple memory corruption issues exist in the bundled version of OpenSSL that allow a remote attacker to cause a denial of service condition or the execution of arbitrary code. (CVE-2016-0799)

- A flaw exists in the bundled version of OpenSSL that allows a cross-protocol Bleichenbacher padding oracle attack known as DROWN (Decrypting RSA with Obsolete and Weakened eNcryption). This vulnerability exists due to a flaw in the Secure Sockets Layer Version 2 (SSLv2) implementation, and it allows captured TLS traffic to be decrypted. A man-in-the-middle attacker can exploit this to decrypt the TLS connection by utilizing previously captured traffic and weak cryptography along with a series of specially crafted connections to an SSLv2 server that uses the same private key. (CVE-2016-0800)

- A flaw exists due to improper handling of specially crafted HTTP requests that contain specific headers. An unauthenticated, remote attacker can exploit this to cause a denial of service condition.

- A flaw exists due to improper handling of malformed HTTP requests. An unauthenticated, remote attacker can exploit this to cause a denial of service condition.

- A flaw exists that is triggered when directly accessing objects. An authenticated, remote attacker can exploit this to disclose search logs.

- A flaw exists due to the failure to honor the sslVersions keyword for TLS protocol versions, preventing users from enforcing TLS policies.

- A path traversal vulnerability exists in the 'collect' command due to improper sanitization of user-supplied input. An authenticated, remote attacker can exploit this, via a specially crafted request, to execute arbitrary code arbitrary code with the privileges of the user running the splunkd process.

- A path traversal vulnerability exists in the 'inputcsv' and 'outputcsv' commands due to improper sanitization of user-supplied input. An authenticated, remote attacker can exploit this, via a specially crafted request, to can access or overwrite file paths.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");

  script_tag(name:"affected", value:"Splunk Enterprise versions 5.0.x prior to 5.0.15, 
        6.0.x prior to 6.0.11, 6.1.x prior to 6.1.10, 6.2.x prior to 6.2.9, 
        6.3.x prior to 6.3.3.4, Light 6.2.x prior to 6.2.9, or Light 6.3.x prior to 6.3.3.4");

  script_tag(name:"solution", value:"Upgrade to Splunk Enterprise 5.0.15 / 6.0.11 / 6.1.10 / 6.2.9 / 6.3.3.4 or later, or Splunk Light 6.2.9 / 6.3.3.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAPKV");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Chiara Paci");
  script_family("Web application abuses");
  script_dependencies("splunk/gb_splunk_detect.nasl");
  script_mandatory_keys("Splunk/installed");
  script_require_ports("Services/www", 8089);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!splport = get_app_port(cpe:CPE)){
  exit(0);
}

if(!splver = get_app_version(cpe:CPE, port:splport)){
  exit(0);
}

if(version_in_range(version:splver, test_version:"6.3.0", test_version2:"6.3.3.3"))
{
  fix = "6.3.3.4";
  VULN = TRUE;
}

else if(version_in_range(version:splver, test_version:"6.1.0", test_version2:"6.1.9"))
{
  fix = "6.1.10";
  VULN = TRUE;
}

else if(version_in_range(version:splver, test_version:"6.2.0", test_version2:"6.2.8"))
{
  fix = "6.2.9";
  VULN = TRUE;
}

else if(version_in_range(version:splver, test_version:"6.0", test_version2:"6.0.10"))
{
  fix = "6.0.11";
  VULN = TRUE;
}

else if(version_in_range(version:splver, test_version:"5.0", test_version2:"5.0.14"))
{
  fix = "5.0.15";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:splver, fixed_version:fix);
  security_message(data:report, port:splport);
  exit(0);
}

exit(99);
