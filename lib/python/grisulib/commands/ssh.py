import socket
import paramiko

#paramiko.common.logging.basicConfig(level=paramiko.common.DEBUG)

from . import base

class HostSSHClient(object):
    def __init__(self,host):
        self._host=host
        self._clients=[]

    def _params(self,host):
        paramiko_data=host.paramiko_data()

        params={
            "username": paramiko_data["auth"]["user"],
            "allow_agent": False,
            #"compress": True,
            "timeout": 60,
        }

        if "disable_sha2_pubkeys_algorithms" in paramiko_data["ssh_config"]:
            params["disabled_algorithms"]= {'pubkeys':['rsa-sha2-512','rsa-sha2-256']}

        if "port" in paramiko_data["ssh_config"]:
            params["port"]=int(paramiko_data["ssh_config"]["port"])

        if "key_filename" in paramiko_data["auth"]:
            params["key_filename"]=paramiko_data["auth"]["key_filename"]
        elif "password" in paramiko_data["auth"]:
            params["password"]=paramiko_data["auth"]["password"]
            params["look_for_keys"]=False
        
        return params

    def _paramiko_connect(self,client,hostadr,**params):
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
        try:
            client.connect(hostadr,**params)
        except paramiko.ssh_exception.AuthenticationException as e:
            e2=base.CommandWrapError("paramiko.ssh_exception.AuthenticationException",e)
            raise e2
        except paramiko.ssh_exception.ChannelException as e:
            e2=base.CommandWrapError("paramiko.ssh_exception.ChannelException",e)
            raise e2
        except paramiko.ssh_exception.SSHException as e:
            print(params)
            e2=base.CommandWrapError("paramiko.ssh_exception.SSHException",e)
            raise e2

        self._clients.append(client)

    def connect(self):
        hostadr=socket.gethostbyname(self._host.name)
        params=self._params(self._host)
        client = paramiko.client.SSHClient()
        if self._host.ssh_bridge is None:
            self._paramiko_connect(client,hostadr,**params)
            return


        bhostadr=socket.gethostbyname(self._host.ssh_bridge.name)
        bparams=self._params(self._host.ssh_bridge)
        bclient = paramiko.client.SSHClient()
        self._paramiko_connect(bclient,bhostadr,**bparams)

        port=params["port"] if "port" in params else 22
        sock = bclient.get_transport().open_channel(
            'direct-tcpip', (hostadr, port), ('', 0)
        )            
        params["sock"]=sock
        self._paramiko_connect(client,hostadr,**params)

    def close(self):
        for client in reversed(self._clients):
            client.close()

    def exec_command(self,*args,**kwargs):
        return self._clients[-1].exec_command(*args,**kwargs)

class SSHCommand(object):

    def _out_parser(self,out):
        return {
            "output": out
        }

    def _build_command(self,**kwargs):
        return "pwd"

    def __call__(self,host,**kwargs):
        ssh_client=HostSSHClient(host)

        cmd=self._build_command(**kwargs)

        ssh_client.connect()
        stdin, stdout, stderr = ssh_client.exec_command(cmd,get_pty=True)

        out = stdout.read().decode()
        err = stderr.read().decode()

        ssh_client.close()

        if err:
            raise base.CommandError(-1,err,out)

        data=self._out_parser(out)
        
        return data

class JavaVersionSSHCommand(SSHCommand):
    def _build_command(self,**kwargs):
        cmd_path=kwargs["cmd_path"]
        return "%s -version" % cmd_path

    def _out_parser(self,out):
        return {
            "output": out.replace('\r\n','\n').strip()
        }

### SyncTools

class SyncToolsCommand(object):
    tool=""

    def _out_parser(self,out):
        return {
            "output": out
        }

    def _build_command(self,**kwargs):
        return self.tool

    def __call__(self,host,**kwargs):

        tools_home=host.synctoolshost.tools_home
        ssh_client=HostSSHClient(host)

        cmd_params={
            "path": tools_home+"/bin",
            "pythonpath": tools_home+"/lib/python",
            "tools_home": tools_home,
            "tools_conf": tools_home+"/etc/config",
        }
        
        cmd_env=[
            'PATH=%(path)s:$PATH',
            'PYTHONPATH=${PYTHONPATH}:%(pythonpath)s',
            'TOOLS_HOME=%(tools_home)s',
            'TOOLS_CONF=%(tools_conf)s',
        ]

        cmd_prefix=( 'export '+" ".join(cmd_env) ) % cmd_params

        cmd=cmd_prefix+";"+self._build_command(**kwargs)

        ssh_client.connect()
        stdin, stdout, stderr = ssh_client.exec_command(cmd,get_pty=True)

        out = stdout.read().decode()
        err = stderr.read().decode()

        ssh_client.close()

        if err:
            raise base.CommandError(-1,err,out)

        data=self._out_parser(out)
        
        return data

class STInfofullos(SyncToolsCommand):
    tool="infofullos"

    def _out_parser(self,out):
        t=out.strip()
        if t.lower() in [ "not implemented", "non implementata" ]:
            raise base.CommandError(0,"%s not implemented on remote host" % self.tool,out)
        return { "o.s.": t }

class STDiscSSLPorts(SyncToolsCommand):
    tool="discsslports"

    def _out_parser(self,out):
        t=out.strip()
        if t.lower() in [ "not implemented", "non implementata" ]:
            raise base.CommandError(0,"%s not implemented on remote host" % self.tool,out)

        ret=[]
        for r in out.strip().split("\n"):
            t=r.strip().split()
            if t[2]=="NO": continue
            port=t[1]
            ip=t[0]
            if t[3]=="SSL":
                ret.append( (ip,port,"ssl") )
            else:
                ret.append( (ip,port,("starttls",t[4])) )
        return ret


class STTestcve(SyncToolsCommand):
    tool="testcve"

    def _build_command(self,**kwargs):
        cve_list=kwargs["cve_list"]
        return self.tool+" "+" ".join(cve_list)

    def _out_parser(self,out):
        rows=out.split("\n")

        t=rows[0].split(":")

        ret={
            "os": {
                "label": t[0].strip(),
                "full": (":".join(t[1:])).strip()
            },
            "cves": [
            ]
        }

        cdata=[]

        for r in rows[1:]:
            r=r.strip()
            if not r: continue
            if r.startswith("cve"):
                if r.endswith("Not implemented"):
                    obj={
                        "cve": r.split(":")[0].strip(),
                        "rows": [],
                        "sa": [ "Not implemented" ]
                    }
                    cdata.append(obj)
                    continue

                t=r.split(" ")
                cve=t[0].strip()
                sa=(" ".join(t[1:])).replace('(','').replace(')','').strip()
                if cdata and cdata[-1]["cve"]==cve:
                    cdata[-1]["sa"].append(sa)
                    continue

                obj={
                    "cve": cve,
                    "sa": [sa],
                    "rows": []
                }
                cdata.append(obj)
                continue

            cdata[-1]["rows"].append(r)

        for cve in cdata:
            obj={
                "cve": cve["cve"],
                "sa": cve["sa"]
            }

            if cve["sa"][0] in [ 'No fix',"Not implemented" ]:
                st=cve["sa"][0]
                reason=""
                obj["status"]={
                    "status": st,
                    "fixed": st=="OK",
                    "reason": reason
                }
                obj["rows"]=[]
                ret["cves"].append(obj)
                continue
                
                

            t=cve["rows"][-1].split()
            st=t[0]
            reason=" ".join(t[1:]).strip().strip("()").strip()
            obj["status"]={
                "status": st,
                "fixed": st=="OK",
                "reason": reason
            }

            obj["rows"]=[self._package(c) for c in cve["rows"][:-1]]
            ret["cves"].append(obj)

        return ret

    def _package(self,row):
        t=row.split()
        st=t[0]
        pkg=t[1]
        if t[3] not in [ ">=","<" ]:
            return {
                "status": st,
                "fixed": st=="OK",
                "package": t[1],
                "msg": " ".join(t[2:])
            }
        return {
            "status": st,
            "fixed": st=="OK",
            "package": t[1],
            "version": t[2],
            "target": t[4],
            "diseq": '&ge;' if t[3]==">=" else '&lt;' 
        }
        
        
