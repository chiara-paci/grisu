import subprocess
#import defusedxml.ElementTree
import re

from . import base

OPENSSL_CMD="/usr/bin/openssl"

class OpenSSLCertificate(object):
    cmd=OPENSSL_CMD
    script_name=""

    # def _argv(self,hostadr,port,**kwargs):
    #     argv=[
    #         "-oX",
    #         "-",
    #         "-Pn",
    #         "-p",
    #         str(port),
    #         "--script",
    #         self.script_name,
    #         hostadr
    #     ]
    #     return argv

    def __call__(self,hostadr,port,**kwargs):
        s_client_cmd=[ 
            self.cmd,
            "s_client", 
            "-connect",
            "%s:%s" % (hostadr,port) 
        ]

        kwargs_s_client={}

        if "servername" in kwargs:
            s_client_cmd+=["-servername", kwargs["servername"] ]

        if "proxychains" in kwargs and kwargs["proxychains"] is not None:
            s_client_cmd=["proxychains"]+s_client_cmd
            kwargs_s_client["cwd"]=kwargs["proxychains"]

        x509_cmd=[ 
            self.cmd, 
            "x509", 
            "-noout", 
            "-text" 
        ]

        x509_proc=subprocess.Popen(
            x509_cmd, 
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        s_client_proc=subprocess.Popen(
            s_client_cmd, 
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs_s_client
        )

        out,err=s_client_proc.communicate(b"q",timeout=60)
        if s_client_proc.returncode!=0:
            raise base.CommandError(
                s_client_proc.returncode,
                err.decode(),
                out.decode()
            )

        out2,err2=x509_proc.communicate(out)
        if x509_proc.returncode!=0:
            raise base.CommandError(
                x509_proc.returncode,
                err2.decode(),
                out2.decode()
            )
        
        data={
            "cmd": " ".join(s_client_cmd),
            "decode_errors": self._x509_err_parser(err2.decode()),
            "raw": out.decode(),
            "connection": self._s_client_parser(out.decode(),err.decode())
        }

        cert=self._x509_out_parser(out2.decode())

        data["certificate"]=cert["Certificate"]


        #cli_stdout=self._s_client_out_parser(out.decode())
            
        return data

    def _s_client_parser(self,out,err): 
        ret_err=self._s_client_err_parser(err) 

        ret_out=self._s_client_out_parser(out) 

        ret={ k: ret_err[k] for k in ret_err if k!="chain" }

        ret["certificate verification"]=ret_out["Server certificate"]
        ret["certificate verification"]["chain"]=ret_out["Certificate chain"]
        ret["certificate verification"]["checks"]=ret_err["chain"]

        ret["info"]=[]

        for r in ret_out["info"]:
            if r.startswith("Verification error:"):
                t=r.split(":")
                ret["certificate verification"]["verification error"]=(":".join(t[1:])).strip()
                continue
            ret["info"].append(r)
        

        if "SSL-Session" in ret_out:
            ret["ssl session"]=ret_out["SSL-Session"]
        else:
            #print(ret_out)
            ret["ssl session"]="-"
        return ret

    def _s_client_out_parser(self,txt): 

        sections=[]
        for r in txt.split('\n'):
            if not r.strip(): continue
            if r.startswith("CONNECTED"): continue
            if r.strip()=='---':
                sections.append([])
                continue
            if r.strip()=='SSL-Session:':
                sections.append(['SSL-Session'])
                continue

            if not sections:
                sections.append([])

            sections[-1].append(r)

        ret={
            "info": []
        }
        for sec in sections:
            if not sec: continue

            if sec[0]=="Certificate chain":
                n=1
                chain={}
                while n<len(sec):
                    t1=sec[n].split(":")
                    t2=sec[n+1].split(":")
                    data={
                        "subject": ":".join(t1[1:]),
                        "issuer": ":".join(t2[1:]),
                    }
                    ind=t1[0].strip().split()[0]
                    chain[ind]=data
                    n+=2


                ret[sec[0]]=chain
                continue

            if sec[0]=="Server certificate":
                n=0
                while n<len(sec):
                    if sec[n].strip('-')=='END CERTIFICATE':
                        n+=1
                        break
                    n+=1

                data={}
                for r in sec[n:]:
                    t=r.split("=")
                    data[t[0].strip()]=("=".join(t[1:])).strip()

                ret[sec[0]]=data
                continue
                
            if sec[0]=="SSL-Session":
                re_data=re.compile('^[0-9a-fA-F]{4} -( [0-9a-fA-F]{2}){8}-([0-9a-fA-F]{2} ){8}.*?$')
                keyval=[]

                data_val=[]
                data_key=None

                for r in sec[1:]:
                    r=r.strip()
                    if not r: continue

                    if r.startswith('TLS session ticket:'):
                        data_key='TLS session ticket'
                        data_val=[]
                        continue

                    if re_data.match(r.strip()):
                        data_val.append(r.strip())
                        continue

                    if data_key is not None:
                        keyval.append( (data_key,data_val) )
                        data_key=None
                        data_val=[]

                    t=r.split(":")
                    key=t[0].strip()
                    val=(":".join(t[1:])).strip()
                    keyval.append( (key,val) )

                # ret["SSL-Session"]=[ r.strip() for r in sec[1:] ]
                ret["SSL-Session"]={ k: v for (k,v) in keyval }
                continue

            ret["info"]+=sec

        return ret

    def _s_client_err_parser(self,txt): 
        data={
            "SNI": True,
            "chain": []
        }

        chain_current=None

        for r in txt.split('\n'):
            r=r.strip()
            if not r: continue
            if r=="Can't use SSL_get_servername":
                data["SNI"]=False
                continue
            if r.startswith("depth"):
                t=r.split(" ")
                depth=t[0].split('=')[1]
                dn=" ".join(t[1:])
                chain_current={
                    "depth": depth,
                    "dn": dn
                }
                data["chain"].append(chain_current)
                continue
            if r.startswith("verify return"):
                t=r.split(":")
                if chain_current is None:
                    chain_current={
                        "depth": "",
                        "dn": ""
                    }
                    data["chain"].append(chain_current)
                chain_current["return"]=t[1]
                continue
            if r.startswith("verify error"):
                t=r.split(":")
                if chain_current is None:
                    chain_current={
                        "depth": "",
                        "dn": ""
                    }
                    data["chain"].append(chain_current)
                chain_current["error"]=":".join(t[1:])
                continue
            if r == "DONE": continue
            if not "errors" in data: data["errors"]=[]
            data["errors"].append(r)
            
        return data

    def _x509_err_parser(self,txt): return txt

    def _x509_out_parser(self,txt): 

        class Elem(object):
            def __init__(self,r):
                nsp=0
                while nsp<len(r):
                    if r[nsp]==" ":
                        nsp+=1
                        continue
                    break
                self.nsp=nsp
                self.text=r.strip()
                self.children=[]
                self.parent=None

            def add_child(self,obj):
                obj.parent=self
                self.children.append(obj)

            def set_parent(self,obj):
                self.parent=obj
                obj.children.append(self)

            _re_exa=re.compile("^[a-fA-F0-9]{2}(:[a-fA-F0-9]{2})+:?$")

            def key_value(self):
                if self._re_exa.match(self.text):
                    return "-",self.text

                t=self.text.split(":")
                if len(t)==1:
                    return "-",self.text

                key=t[0].strip()

                if key.endswith("URI"):
                    return "-",self.text

                if key.endswith("DNS"):
                    return "-",self.text
                    

                if len(t)>1:
                    val=(":".join(t[1:])).strip()
                else:
                    val=""
                return key,val

            def _reduce_children(self,children_ser):
                txt=""
                for ch in children_ser:
                    if "data" in ch:
                        return self._to_dict(children_ser)
                    if "text" not in ch:
                        return self._to_dict(children_ser)
                    txt+=ch["text"]
                return txt

            def _to_dict(self,children_ser):
                ret={}

                for ch in children_ser:
                    if ch["key"] not in ret:
                        ret[ch["key"]]=ch["value"]
                        continue
                    if type(ret[ch["key"]]) is list:
                        ret[ch["key"]].append(ch["value"])
                        continue
                    ret[ch["key"]]=[
                        ret[ch["key"]],
                        ch["value"]
                    ]

                return ret

            def serialize(self):
                key,val=self.key_value()

                ret={}
                #     "indent": self.nsp,
                # }

                if key=="-":
                    if self.children:
                        ret["key"]=val
                    else:
                        ret["text"]=val
                else:
                    ret["key"]=key
                    if val:
                        ret["value"]=val

                if not self.children: return ret

                data=self._reduce_children([ ch.serialize() for ch in self.children ])

                if "value" not in ret:
                    ret["value"]=data
                    return ret

                if not (type(data) is str):
                    ret["value"]={
                        "text": ret["value"],
                        "data": data,
                    }
                    return ret

                if not self._re_exa.match(ret["value"]):
                    ret["value"]={
                        "text": ret["value"],
                        "data": data,
                    }
                    return ret

                if not self._re_exa.match(data):
                    ret["value"]={
                        "text": ret["value"],
                        "data": data,
                    }
                    return ret

                ret["value"]+=data

                return ret


        data=[]
        previous=None

        for r in txt.split('\n'):
            if not r.strip(): continue

            nsp=0
            while nsp<len(r):
                if r[nsp]==" ":
                    nsp+=1
                    continue
                break

            obj=Elem(r)
            data.append(obj)

        tree=[]
        for n in range(len(data)):
            obj=data[n]
            if obj.nsp==0:
                tree.append(obj)
                continue
            for i in range(1,n+1):
                if obj.nsp>data[n-i].nsp:
                    obj.set_parent(data[n-i])
                    break
            else:
                tree.append(obj)


        ret={ o["key"]: o["value"] for o in [ obj.serialize() for obj in tree ] }
                 
        return ret


