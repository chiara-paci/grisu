import subprocess
import defusedxml.ElementTree
import re
import os.path
import html

from . import base

SUDO_CMD="/usr/bin/sudo"
TIMEOUT_CMD="/usr/bin/timeout"
OVAS_CMD="/usr/bin/openvas-nasl"
OVAS_PLUGINS="/var/lib/openvas/plugins"

class OpenVASBase(object):
    cmd=OVAS_CMD
    plugins_dir=OVAS_PLUGINS
    sudo=SUDO_CMD
    plugins=[]
    timeout=60
    timeout_cmd=TIMEOUT_CMD

    def _args_ports(self,port):
        return [
            '--kb',
            'Ports/tcp/%s=1' % port,
        ]
        
    def __call__(self,hostadr,port,**kwargs):
        cmd=[
            self.sudo,
            self.timeout_cmd,
            str(self.timeout),
            self.cmd,
            "--disable-signing",
            "--include-dir",
            self.plugins_dir,
        ]

        for p in self.plugins:
            if p.startswith("/"):
                cmd.append(p)
            else:
                cmd.append(os.path.join(self.plugins_dir,p))

        cmd+=[
            "--target",
            hostadr,
        ]

        cmd+=self._args_ports(port)

        run_cmd="%s" % (' '.join(cmd[1:]))

        kwargs_c={
            "capture_output": True,
            #"timeout": self.timeout+5
        }

        if "proxychains" in kwargs and kwargs["proxychains"] is not None:
            cmd.insert(1,"proxychains")
            kwargs_c["cwd"]=kwargs["proxychains"]

        try:
            compl=subprocess.run(
                cmd,
                **kwargs_c,
            )
        except subprocess.TimeoutExpired as e:
            ekwargs={
                "error": "Timeout expired after %d seconds" % e.timeout
            }
            if e.stdout is not None:
                ekwargs['output']=e.stdout.decode()
            if e.stderr is not None:
                ekwargs['error']+='\n'+e.stderr.decode()

            raise base.CommandWrapError(
                "subprocess.TimeoutExpired",
                e,
                **ekwargs
            )

        if compl.returncode!=0 and compl.stderr:
            raise base.CommandError(compl.returncode,compl.stderr,compl.stdout)

        err=compl.stderr.decode()
        out=compl.stdout.decode()


        #print(out)

        #root=defusedxml.ElementTree.fromstring(out)
        data=self._out_parser(out)

        data["command_line"]=run_cmd
        
        return data


    def _out_parser(self,out):
        ret={
            "output": out
        }
        return ret



class OpenVASSSHWeakEncryptionAlgos(OpenVASBase):
    plugins=[
        'gb_ssh_algos.nasl',
        '2016/gb_ssh_weak_encryption_algos.nasl'
    ]

    def _out_parser(self,out):
        ret={}

        section=''
        sub=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("The"):
                section=r.strip().strip(':')
                sub=''
                continue
            if section.startswith("The remote"):
                if section not in ret: ret[section]=[]
                ret[section].append(r.strip())
                continue
            if r.endswith(":"):
                sub=r.strip().strip(":")
                continue
            if section not in ret: ret[section]={}
            if sub not in ret[section]: ret[section][sub]=[]
            ret[section][sub]+=[ x.strip() for x in r.split(",") ]
                

        return ret

class OpenVASSSHWeakHmacAlgos(OpenVASBase):
    plugins=[
        'gb_ssh_algos.nasl',
        '2016/gb_ssh_weak_hmac_algos.nasl'
    ]

    def _out_parser(self,out):
        ret={}

        section=''
        sub=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("The"):
                section=r.strip().strip(':')
                sub=''
                continue
            if section.startswith("The remote"):
                if section not in ret: ret[section]=[]
                ret[section].append(r.strip())
                continue
            if r.endswith(":"):
                sub=r.strip().strip(":")
                continue
            if section not in ret: ret[section]={}
            if sub not in ret[section]: ret[section][sub]=[]
            ret[section][sub]+=[ x.strip() for x in r.split(",") ]
                

        return ret


# /var/lib/openvas/plugins/ssh_proto_version.nasl /var/lib/openvas/plugins/2011/gb_ssh_authentication_bypass_vuln.nasl -X --kb="Ports/tcp/22=1" 
# "Deprecated SSH-1 Protocol Detection"

# The remote SSH Server supports the following SSH Protocol Versions:
# 1.33
# 1.5
# 1.99
# 2.0

# SSHv1 Fingerprint: f9:50:02:9b:f0:5c:32:b7:93:6b:eb:fc:ce:ea:5c:b7
# The service is providing / accepting the following deprecated versions of the SSH protocol which have known cryptographic flaws:

# 1.33
# 1.5


# "Deprecated SSH-1 Protocol Detection"
class OpenVASSSHVersion1(OpenVASBase):
    plugins=[
        'ssh_proto_version.nasl',
        '2011/gb_ssh_authentication_bypass_vuln.nasl',
    ]

    def _out_parser(self,out):
        ret={}

        if not out.strip():
            return {
                "nasl error": "no output",
                "output": ""
            }

        section=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("SSHv"):
                t=r.split(':')
                ret[t[0].strip()]=(":".join(t[1:])).strip()
                continue
            if r.startswith("The"):
                section=r.strip().strip(':')
                continue
            if section not in ret: ret[section]=[]
            ret[section].append(r.strip())
                

        return ret


class OpenVASHttpsCrime(OpenVASBase):
    plugins=[
        'secpod_open_tcp_ports.nasl',
        'gb_tls_version_get.nasl',
        '2017/gb_tls_crime.nasl',
    ]
    
    def _args_ports(self,port):
        return [
            '--kb',
            'Ports/tcp/%s=1' % port,
            '--kb',
            'Services/www=%s' % port,
            '--kb',
            'Transports/TCP/%s=2' % port,
        ]

    def _out_parser(self,out):
        ret={}

        section=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("Open"):
                section=r.strip().strip(':')
                continue
            if r.startswith("The"):
                section=r.strip().strip(':')
                continue
            if section not in ret:
                ret[section]=[]
            if section.startswith("The remote SSL/TLS"):
                ret[section].append(r.strip())
                continue
            t=[x.strip() for x in r.split(':')]
            ret[section].append(t)

        return ret

class OpenVASHttpsWeakHashAlgo(OpenVASBase):
    plugins=[
        'secpod_open_tcp_ports.nasl',
        'gb_tls_version_get.nasl',
        'gb_ssl_tls_cert_chain_get.nasl',
        '2016/gb_ssl_tls_weak_hash_algo.nasl',
    ]
    
    def _args_ports(self,port):
        return [
            '--kb',
            'Ports/tcp/%s=1' % port,
            '--kb',
            'Services/www=%s' % port,
            '--kb',
            'Transports/TCP/%s=2' % port,
        ]

    def _out_parser(self,out):
        ret={}

        section=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("Open"):
                section=r.strip().strip(':')
                continue
            if r.startswith("The"):
                section=r.strip().strip(':')
                continue
            if section not in ret:
                ret[section]=[]
            if not section.startswith("The following certificates are part"):
                ret[section].append(r.strip())
                continue
            t=[x.strip() for x in r.split(':')]
            if t[0]=="Subject":
                ret[section].append([])
            ret[section][-1].append(t)

        return ret

# SSL/TLS: Server Certificate / Certificate in Chain with RSA keys less than 2048 bits
class OpenVASHttpsRsaKey2048(OpenVASBase):
    plugins=[
        'secpod_open_tcp_ports.nasl',
        'gb_tls_version_get.nasl',
        'gb_ssl_tls_cert_chain_get.nasl',
        '2021/gb_ssl_tls_rsa_key_2048bits.nasl',
    ]
    
    def _args_ports(self,port):
        return [
            '--kb',
            'Ports/tcp/%s=1' % port,
            '--kb',
            'Services/www=%s' % port,
            '--kb',
            'Transports/TCP/%s=2' % port,
        ]

    def _out_parser(self,out):
        ret={}

        section=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("Open"):
                section=r.strip().strip(':')
                continue
            if r.startswith("The"):
                section=r.strip().strip(':')
                continue
            if section not in ret:
                ret[section]=[]
            if not section.startswith("The remote SSL/TLS server is using the following certificate"):
                ret[section].append(r.strip())
                continue
            t=[x.strip() for x in r.split(':')]
            
            ret[section].append({
                "public-key-size": t[0],
                "public-key-algorithm": t[1],
                "serial": t[2],
                'issuer': t[3],
            })

        return ret

# "PHP < 7.4.31, 8.0.x < 8.0.24, 8.1.x < 8.1.11 Security Update - Linux"
# script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
#  script_mandatory_keys("php/detected", "Host/runs_unixoide");

#proxychains openvas-nasl -X --kb 'Services/www=80' --kb 'Ports/tcp/443=1' -t 192.168.219.18 -i /var/lib/openvas/plugins gb_php_http_detect.nasl  /var/lib/openvas/plugins/2023/php/gb_php_mult_vuln_aug23_lin.nasl 

class OpenVASPhpLinuxSep2022(OpenVASBase):
    plugins=[
        'gb_php_http_detect.nasl',
        '2022/php/gb_php_mult_vuln_sep22_lin.nasl',
    ]

    def _args_ports(self,port):
        return [
            '--kb',
            'Ports/tcp/%s=1' % port,
            '--kb',
            'Services/www=80', # deve essere 80 se no la detect non funziona (potrebbe bastare una http qualsiasi?)
        ]

    def _out_parser(self,out):
        ret={}
        section=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("Detected PHP"):
                section=r.strip().strip(':')
                continue
            if r.startswith("Concluded from "):
                section=r.strip().strip(':')
                continue
            if r.startswith("Installed version:"):
                section="Vulnerable"

            if section.startswith("Concluded from "):
                if section not in ret:
                    ret[section]=[]
                ret[section].append(r.strip())
                continue

            if section not in ret:
                ret[section]={}

            if r.strip()=="Installation": continue

            t=r.split(':')
            k=t[0].strip()
            v=(':'.join(t[1:])).strip()
            ret[section][k]=v
        return ret

class OpenVASPhpLinuxAug2023(OpenVASPhpLinuxSep2022):
    plugins=[
        'gb_php_http_detect.nasl',
        '2023/php/gb_php_mult_vuln_aug23_lin.nasl',
    ]

class OpenVASPhpLinuxOct2022(OpenVASPhpLinuxSep2022):
    plugins=[
        'gb_php_http_detect.nasl',
        '2022/php/gb_php_mult_vuln_oct22_lin.nasl',
    ]

class OpenVASPhpLinuxDec2018(OpenVASPhpLinuxSep2022):
    plugins=[
        'gb_php_http_detect.nasl',
        '2018/php/gb_php_mult_vuln_dec18_lin.nasl',
    ]

# PHP Directory Traversal Vulnerability - Jul16 (Linux)

class OpenVASPhpLinuxJul2016(OpenVASPhpLinuxSep2022):
    plugins=[
        'gb_php_http_detect.nasl',
        '2016/gb_php_dir_traversal_vuln_lin.nasl',
    ]


    
# Detected PHP

# Version:       8.0.28
# Location:      80/tcp
# CPE:           cpe:/a:php:php:8.0.28

# Concluded from version/product identification result:
# X-Powered-By: PHP/8.0.28

# Installed version: 8.0.28
# Fixed version:     8.0.30
# Installation
# path / port:       80/tcp



class OpenVASSplunkAgentUnsupported(OpenVASBase):
    plugins=[
        "find_service.nasl", 
        "/home/chiara/dragut/dragutplugins/nasl/splunk/drg_splunk_agent_detect.nasl",
        "/home/chiara/dragut/dragutplugins/nasl/splunk/drg_splunk_end_of_support.nasl",
    ]

    def _args_ports(self,port):
        return [
            '--kb',
            'Ports/tcp/%s=1' % port,
            '--kb',
            'Services/www=%s' % port,
        ]

    def _out_parser(self,out):
        ret={}
        section=''
        for r in out.split('\n'):
            if not r.strip(): continue
            if r.startswith("Detected Splunk"):
                section="Detected Splunk Agent"
                continue
            if r.startswith("Concluded from "):
                section=r.strip().strip(':')
                continue
            if r.startswith("Extra information:"):
                section="Detected Splunk Agent"
                continue
                
            if r.startswith("Installed version:") or r.startswith("Fixed version:"):
                section="Vulnerable"

            if section.startswith("Concluded from "):
                if section not in ret:
                    ret[section]=[]
                ret[section].append(html.escape(r.strip()))
                continue

            if section not in ret:
                ret[section]={}

            t=r.split(':')
            k=t[0].strip()
            v=(':'.join(t[1:])).strip()
            ret[section][k]=v
        return ret

class OpenVASSplunkAgent2017XssVuln(OpenVASSplunkAgentUnsupported):
    plugins=[
        "find_service.nasl", 
        "/home/chiara/dragut/dragutplugins/nasl/splunk/drg_splunk_agent_detect.nasl",
        "2017/gb_splunk_enterprise_xss_vuln.nasl",
    ]

class OpenVASSplunkAgentNessusPlugin90705Drown(OpenVASSplunkAgentUnsupported):
    plugins=[
        "find_service.nasl", 
        "/home/chiara/dragut/dragutplugins/nasl/splunk/drg_splunk_agent_detect.nasl",
        "/home/chiara/dragut/dragutplugins/nasl/splunk/drg_nessus_plugin_90705_drown.nasl",
    ]

