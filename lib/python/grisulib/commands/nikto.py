import subprocess
import defusedxml.ElementTree
import re

from . import base

NIKTO_CMD="/home/chiara/dragut/vendor/nikto/program/nikto.pl"
NIKTO_CONF="/home/chiara/dragut/vendor/nikto/program/nikto_dragut.conf"

#testssl.sh -U --jsonfile-pretty /tmp/prova3.json --ip 194.153.172.13 https://wpadsrv.group.global
#testssl.sh -U --jsonfile-pretty /tmp/prova3.json https://194.153.172.13 

#./nikto.pl -h https://194.153.172.13 -Plugins x

class NiktoBase(object):
    cmd=NIKTO_CMD
    conf=NIKTO_CONF
    plugins=[]
    timeout=60

    def __call__(self,hostadr,port,**kwargs):
        cmd=[
            "/usr/bin/perl", 
            self.cmd,
            "-config",
            self.conf,
        ]

        if port in [80,'80']:
            cmd+=["-h",'http://%s' % hostadr]
        elif port in [443,'443']:
            cmd+=["-h",'https://%s' % hostadr]
        else:
            cmd+=["-h",'https://%s:%s' % (hostadr,port)]

        if self.plugins:
            cmd+=[
                "-Plugins",
                ";".join(self.plugins)
            ]

        run_cmd="./nikto.pl %s" % (' '.join(cmd[2:]))

        #if "servername" in kwargs:
        #    cmd+=[
        #        '-vhost',
        #        kwargs["servername"],
        #    ]

        kwargs_c={
            "capture_output": True,
            "timeout": self.timeout
        }

        #if "proxychains" in kwargs and kwargs["proxychains"] is not None:
        #    cmd=["proxychains"]+cmd
        #    kwargs_c["cwd"]=kwargs["proxychains"]


        compl=subprocess.run(
            cmd,
            **kwargs_c,
            #capture_output=True,
            #timeout=60
        )

        if compl.returncode!=0 and compl.stderr:
            raise base.CommandError(compl.returncode,compl.stderr,compl.stdout)

        err=compl.stderr.decode()
        out=compl.stdout.decode()
        #root=defusedxml.ElementTree.fromstring(out)
        data=self._out_parser(out)

        data["command_line"]=run_cmd
        
        return data


    def _out_parser(self,out):
        re_req=re.compile(r"\+ \d+ requests: \d+ error\(s\) and \d+ item\(s\) reported on remote host")
        re_tst=re.compile(r"\+ \d+ host\(s\) tested")
        ret={
            "info": {},
            "data": []
        }
        for r in out.split("\n"):
            if r.startswith('-----------------------'): continue
            if r.startswith('- Nikto'):
                ret["info"]["version"]=r.replace('- Nikto','').strip()
                continue
            if not r.strip(): continue
            info=False
            for k in [
                    'Target IP',
                    'Target Hostname',
                    'Target Port',
                    'Start Time',
                    'End Time',
                    'Server',
            ]:
                if not r.startswith("+ "+k): continue
                r=r.replace("+ %s:" % k,'').strip()
                ret["info"][k]=r
                info=True
            if info: continue

            if r.startswith("+ SSL Info"):
                r=r.replace("+ SSL Info:",'').replace("Subject:",'').strip()
                ret["info"]["SSL Info"]={
                    "Subject": r
                }
                continue
            if "SSL Info" in ret["info"]:
                sslinfo=False
                for k in [ "Ciphers", "Issuer" ]:
                    if r.strip().startswith(k+":"):
                        r=r.replace(k+":",'').strip()
                        ret["info"]["SSL Info"][k]=r
                        sslinfo=True
                        break
                if sslinfo: continue

            if re_req.match(r.strip()):
                ret["info"]["Requests"]=r.strip()
                continue

            if re_tst.match(r.strip()):
                ret["info"]["Hosts"]=r.strip()
                continue

            ret["data"].append(r)
        return ret



class NiktoHttpOptions(NiktoBase):
    plugins=['httpoptions']

    def _out_parser(self,out):
        data=NiktoBase._out_parser(self,out)
        ret={}
        for k in data:
            if k!="data":
                ret[k]=data[k]
                continue
            for r in data[k]:
                if r.startswith("+ OPTIONS: Allowed HTTP Methods:"):
                    r=r.replace("+ OPTIONS: Allowed HTTP Methods:","").replace('.','').strip()
                    ret["methods"]=[x.strip() for x in r.split(',')]
                    continue
                if "data" not in ret: ret["data"]=[]
                ret["data"].append(r)
        return ret

class NiktoTests(NiktoBase):
    plugins=['tests']

    timeout=None

    def _out_parser(self,out):
        data=NiktoBase._out_parser(self,out)
        ret={
            "results": {}
        }

        re_item=re.compile("\+ (?P<path>.+?): (?P<cat>.+?)\. See: (?P<ref>.*)")

        for k in data:
            if k!="data":
                ret[k]=data[k]
                continue
            for r in data[k]:
                m=re_item.search(r.strip())
                if not m:
                    if "data" not in ret: ret["data"]=[]
                    ret["data"].append(r)
                    continue
                if m.group("cat") not in ret["results"]:
                    ret["results"][m.group("cat")]={
                        "see": m.group("ref"),
                        "finding": []
                    }
                ret["results"][m.group("cat")]["finding"].append(m.group("path"))
        return ret

# type(+ /icons/: Directory indexing found. See: http://projects.webappsec.org/w/page/13246922/Directory%20Indexing,
#        + /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/,
