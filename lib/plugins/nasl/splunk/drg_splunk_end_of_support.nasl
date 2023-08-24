# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.300003");
  script_version("2023-08-18T10:00:00+0000");
  script_tag(name:"cvss_base", value:"10");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-18 10:00:00 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Splunk Unsupported Version Detection");

  script_tag(name:"summary", value:"The remote host contains an unsupported version Splunk.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"According to its version, the installation of Splunk on the remote host is no longer supported.

Lack of support implies that no new security patches for the product will be released by the vendor. As a result, it is likely to contain security vulnerabilities.");


  script_tag(name:"affected", value:"Splunk Enterprise versions 6.x, 7.x, 8.0.x, 8.1.x");

  script_tag(name:"solution", value:"Upgrade to a version of Splunk that is currently supported.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.splunk.com/en_us/legal/splunk-software-support-policy.html");

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

if(version_is_less(version:splver, test_version:"8.2")){
  fix = "8.2";
  report = report_fixed_ver(installed_version:splver, fixed_version:fix);
  security_message(data:report, port:splport);
  exit(0);
}

exit(99);
