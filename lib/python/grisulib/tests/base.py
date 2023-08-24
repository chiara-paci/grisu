import socket
import urllib.parse
import json

import os.path

from .. import commands
from . import base

class VulnTest(object):
    flags=""
    name=""
    command=None

    def __init__(self):
        self._cmd=self.command()

    def _kwargs(self,target): return {}

    def html(self,out,indent="",pre=True): 
        ret=""
        if pre: ret+="<pre>"
        if type(out) not in [ dict, list ]:
            ret+=str(out)
            if pre: ret+="</pre>"
            return ret

        if type(out) is list:
            ret+="[" 
            for k in out:
                ret+="\n    %s%s," % (
                    indent,
                    self.html(k,indent=indent+"    ",pre=False)
                )
            ret+='\n%s]' % indent
            if pre: ret+="</pre>"
            return ret

        ret+="{" 
        for k in out:
            ret+="\n    %s%s: %s," % (
                indent,k,
                self.html(out[k],indent=indent+"    ",pre=False)
            )
        ret+='\n%s}' % indent
        if pre: ret+="</pre>"
        return ret

    def txt(self,ret_exec):
        target,valid,output=ret_exec
        ret="%s - %s\n\n" % (
            "OK" if valid else "NO",
            str(target)
        )
        ret+=json.dumps(output,indent=4)
        return ret
        
    def __call__(self,target_list,proxychains=None,secondary=False):
        return [ (t,False,"Not implemented") for t in target_list ]

class OnSocketVulnTest(VulnTest):
    default_port=443
    
    class Call(object):
        def __init__(self,hostadr,port,**kwargs):
            self._hostadr=hostadr
            self._port=port
            self._kwargs=kwargs
            self.out=None
            self.exception=None

        def run(self,cmd):
            try:
                self.out=cmd(self._hostadr,self._port,**self._kwargs)
            except Exception as e:
                self.exception=e
                raise e
            return self.out

        def __eq__(self,other):
            if self._hostadr!=other._hostadr: return False
            if self._port!=other._port: return False
            if len(self._kwargs)!=len(other._kwargs): return False

            for k in self._kwargs:
                if k not in other._kwargs: return False
                if self._kwargs[k]!=other._kwargs[k]: return False
            return True

        def __ne__(self,other): return not self.__eq__(other)

        def __str__(self):
            return "%s:%s %s" % (self._hostadr,self._port,str(self._kwargs))

    def __init__(self):
        VulnTest.__init__(self)
        self._cache=[]

    def _cached_cmd(self,hostadr,port,**kwargs):
        current=self.Call(hostadr,port,**kwargs)
        print("Try: [%s] %s" % (self.name,str(current)))
        for c in self._cache:
            if c==current: 
                print("    Cached: %s" % str(c))
                if c.out is not None:
                    return c.out
                elif c.exception is not None:
                    raise c.exception
                current=c
                break
        else:
            print("    New: %s" % str(current))
            self._cache.append(current)
        return current.run(self._cmd)

    def _kwargs(self,target,proxychains=None):
        proxychains=target.proxychains if target.proxychains is not None else proxychains
        if proxychains is None: return {}
        return {
            "proxychains": proxychains
        }

    def _single_call(self,target,proxychains=None,secondary=False):
        hostadr=target.get_ip(force_secondary=secondary)
        port=target.port if target.port is not None else self.default_port
        kwargs=self._kwargs(target,proxychains=proxychains)

        try:
            out=self._cached_cmd(hostadr,port,**kwargs)
            out["call"]={}
            out["call"]["hostadr"]=hostadr
            out["call"]["port"]=port
            out["call"]["kwargs"]=kwargs
        except commands.CommandError as e:
            return (target,False,e)
        except commands.CommandWrapError as e:
            return (target,False,e)

        return (target,True,out)

    def __call__(self,target_list,proxychains=None,secondary=False):
        ret=[]
        for target in target_list:
            out=self._single_call(target,proxychains=proxychains,secondary=secondary)
            ret.append(out)
        return ret

class OnSNISocketVulnTest(OnSocketVulnTest):
    def _kwargs(self,target,**kwargs):
        ret=OnSocketVulnTest._kwargs(self,target,**kwargs)
        if target.servername is not None:
            ret["servername"]=target.servername
        return ret

