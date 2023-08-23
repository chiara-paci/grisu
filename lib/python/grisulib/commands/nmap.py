import subprocess
import defusedxml.ElementTree
import os.path

from . import base

NMAP_CMD="/usr/bin/nmap"
SUDO_CMD="/usr/bin/sudo"
TIMEOUT_CMD="/usr/bin/timeout"

class NmapScript(object):
    cmd=NMAP_CMD
    script_name=""

    def _argv(self,hostadr,port,**kwargs):
        argv=[
            "-oX",
            "-",
            "-Pn",
            "-p",
            str(port),
            "--script",
            self.script_name,
            hostadr
        ]
        return argv

    def __call__(self,hostadr,port,**kwargs):
        argv=self._argv(hostadr,port,**kwargs)
        cmd=[self.cmd]+argv
        kwargs_c={
            "capture_output": True,
            "timeout": 60
        }

        if "proxychains" in kwargs and kwargs["proxychains"] is not None:
            cmd=["proxychains"]+cmd
            kwargs_c["cwd"]=kwargs["proxychains"]

        print(cmd)

        compl=subprocess.run(
            cmd,
            **kwargs_c,
            #capture_output=True,
            #timeout=60
        )

        if compl.returncode!=0:
            raise base.CommandError(compl.returncode,compl.stderr,compl.stdout)

        err=compl.stderr.decode()
        out=compl.stdout.decode()
        root=defusedxml.ElementTree.fromstring(out)
        data=self._out_parser(root)
        
        return data

    def _out_parser(self,tree):
        ret={
            "info": {
                "nmaprun": tree.attrib
            },
            "hosts": [],
        }
        for ch in tree:
            if ch.tag=="runstats":
                ret["info"]["runstats"]={}
                for ch1 in ch:
                    ret["info"]["runstats"][ch1.tag]=ch1.attrib
                continue
            if ch.tag!="host":
                ret["info"][ch.tag]=ch.attrib
                continue
            ret["hosts"].append(self._host(ch))
        return ret

    def _host(self,elem):
        ret={
            "info": elem.attrib,
            "ports": []
        }
        for ch in elem:
            if ch.tag!="ports":
                ret[ch.tag]=ch.attrib
                continue
            for subch in ch:
                ret["ports"].append(self._port(subch))
        return ret

    def _port(self,elem):
        ret={
            "info": elem.attrib,
        }
        for ch in elem:
            if ch.tag!="script":
                ret[ch.tag]=ch.attrib
                continue
            ret[ch.tag]=ch.attrib["id"]
            for subch in ch:
                ret=self._script_child(ret,subch)
        return ret

    def _script_child(self,ret,child):
        return ret

class NmapScriptUdp(NmapScript):
    sudo=SUDO_CMD
    timeout=60
    timeout_cmd=TIMEOUT_CMD

    def _proxychains_to_proxy(self,proxychains):
        if proxychains is None: return None
        fname=os.path.join(proxychains,'proxychains.conf')
        with open(fname) as fd:
            for r in fd.readlines():
                r=r.strip()
                if r.startswith('socks5'):
                    t=r.split()
                    # nmap vuole socks4
                    return "socks4://%s:%s" % (t[1],t[2]) 
        return None


    def _argv(self,hostadr,port,**kwargs):
        argv=NmapScript._argv(self,hostadr,port,**kwargs)
        argv+=['-sU']
        if "proxychains" in kwargs and kwargs["proxychains"] is not None:
            proxy=self._proxychains_to_proxy(kwargs["proxychains"])
            if proxy is not None:
                argv+=[
                    "--proxies",
                    proxy
                ]
        return argv

    def __call__(self,hostadr,port,**kwargs):
        argv=self._argv(hostadr,port,**kwargs)

        cmd=[
            self.sudo,
            self.timeout_cmd,
            str(self.timeout),
            self.cmd
        ]+argv

        kwargs_c={
            "capture_output": True
        }

        print(cmd)

        compl=subprocess.run(
            cmd,
            **kwargs_c
        )

        if compl.returncode!=0:
            raise base.CommandError(compl.returncode,compl.stderr,compl.stdout)

        err=compl.stderr.decode()
        out=compl.stdout.decode()
        root=defusedxml.ElementTree.fromstring(out)
        data=self._out_parser(root)
        
        return data


# nmap http

class NmapScriptHttp(NmapScript):

    def _argv(self,hostadr,port,**kwargs):
        argv=[
            "-oX",
            "-",
            "-Pn",
            "-p",
            str(port),
            "--script",
            self.script_name,
        ]
        
        if "servername" in kwargs and kwargs["servername"] is not None:
            argv+=["--script-args","tls.servername=%s" % kwargs["servername"] ]

        argv.append(hostadr)
        return argv

class NmapSSLEnumCiphers(NmapScriptHttp):
    script_name="ssl-enum-ciphers"

    def _script_child(self,ret,child):
        if "protocols" not in ret:
            ret["protocols"]=[]
        if "results" not in ret:
            ret["results"]={}

        if child.tag=="elem":
            ret["results"][child.attrib["key"]]=child.text
            return ret

        ret["protocols"].append(self._ssl_protocol(child))
        return ret

    def _ssl_protocol(self,elem):
        ret={
            "name": elem.attrib["key"],
            "ciphers": []
        }
        for ch in elem:
            if ch.tag=="elem":
                ret[ch.attrib["key"]]=ch.text
                continue
            if ch.attrib["key"]!="ciphers":
                ret[ch.attrib["key"]]=[]
                for subch in ch:
                    ret[ch.attrib["key"]].append(subch.text)
                    continue
                continue
            for subch in ch:
                d={}
                for ech in subch:
                    d[ech.attrib["key"]]=ech.text
                ret["ciphers"].append(d)
        return ret

class NmapSSLCertificate(NmapScriptHttp):
    script_name="ssl-cert"

    def _script_child(self,ret,child):
        if "cert_info" not in ret:
            ret["cert_info"]={}

        if child.tag=="elem":
            ret["cert_info"][child.attrib["key"]]=child.text
            return ret

        if "key" in child.attrib and child.attrib["key"] not in ["extensions"]:
            ret[child.attrib["key"]]=self._table(child)
            return ret

        ret["extensions"]=self._extensions(child)
        return ret

    def _extensions(self,elem):
        ret=[]
        print("++++",elem.tag,elem.attrib)
        for ch in elem:
            ret.append(self._ext_table(ch))
        return ret

    def _ext_table(self,elem):
        ret={}
        for ch in elem:
            if ch.tag!="elem": continue
            k=ch.attrib["key"]
            if k=="critical":
                ret[k]=(ch.text.strip()=="true")
            else:
                ret[k]=ch.text
        return ret

    def _table(self,elem):
        ret={}
        for ch in elem:
            if ch.tag=="elem":
                ret[ch.attrib["key"]]=ch.text
        return ret

class NmapHttpTrace(NmapScriptHttp):
    script_name="http-trace"

    def _port(self,elem):
        ret={
            "info": elem.attrib,
        }
        for ch in elem:
            if ch.tag!="script":
                ret[ch.tag]=ch.attrib
                continue
            ret[ch.tag]=ch.attrib["id"]
            ret["output"]=ch.attrib["output"]
        
        if "output" not in ret:
            ret["output"]=""

        return ret

# Nmap ssh

class NmapSSH2EnumAlgos(NmapScript):
    script_name="ssh2-enum-algos"


    def _argv(self,hostadr,port,**kwargs):
        argv=[
            "-oX",
            "-",
            "-Pn",
        ]
        argv+=[
            "-p",
            str(port),
        ]

        if port not in [ 22, '22']:
            argv+=['-sV']

        argv+=[
            "--script",
            self.script_name,
            hostadr
        ]

        return argv

    def _script_child(self,ret,child):
        if "algorithms" not in ret:
            ret["algorithms"]=[]
        ret["algorithms"].append(self._algorithms(child))
        return ret

    def _algorithms(self,elem):
        ret={
            "name": elem.attrib["key"],
            "list": []
        }
        for ch in elem:
            if ch.tag=="elem":
                ret["list"].append(ch.text)
                continue
        return ret

class NmapMDNSDetection(NmapScriptUdp):
    script_name="dns-service-discovery"
