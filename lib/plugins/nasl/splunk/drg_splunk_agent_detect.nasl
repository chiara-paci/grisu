# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Personal: 1.3.6.1.4.1.25623.1.0.30NNNN

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.300001");
  script_version("2023-08-17T11:10:00+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-08 11:10:00 +0000 (Thu, 17 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-08 11:10:00 +0000 (Thu, 17 Aug 2023)");
  script_name("Splunk Detection");

  script_tag(name:"summary", value:"Detects the installed version of Splunk.

  This script sends an HTTP GET request and tries to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www.splunk.com/");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8089);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:8089);

dir="/";

install = dir;

buf = http_get_cache(item: dir , port: port);

if (egrep(pattern:'Server: Splunkd', string: buf, icase: TRUE) &&
    (buf =~ '.*<generator build=".*" version=".*"/>.*')) {

  vers = "unknown";
  
  version = eregmatch(string:buf, pattern:'.*<generator build=".*" version="([0-9.]+)"/>.*',icase:TRUE);
     
  if (!isnull(version[1]))
    vers = version[1];
  
  b = eregmatch(string:buf, pattern:'.*<generator build="([0-9a-z.]+)" version=".*"/>.*',icase:TRUE);
  
  if (!isnull(b[1]))
    build = b[1];
  
  set_kb_item(name: string("www/", port, "/splunk"), value: string(vers));
  if (!isnull(build)) {
    set_kb_item(name: string("www/", port, "/splunk/build"), value: string(build));
    extra = "Build:  " + build;
  }
  
  set_kb_item(name:"Splunk/installed", value:TRUE);
  
  cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:splunk:splunk:");
  if (!cpe)
    cpe = "cpe:/a:splunk:splunk";
  
  register_product(cpe: cpe, location: install, port: port, service: "www");
  
  log_message(data: build_detection_report(app: "Splunk", version: vers, install: install, cpe: cpe,
					   concluded: version[0], extra: extra),
	      port: port);
  exit(0);
} 

  
exit(0);
  
