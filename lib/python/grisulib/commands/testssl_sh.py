import subprocess
import defusedxml.ElementTree
import tempfile
import os.path
import json

from . import base

TESTSSL_CMD="/home/chiara/dragut/vendor/testssl.sh-3.0.8/testssl.sh"

#testssl.sh -U --jsonfile-pretty /tmp/prova3.json --ip 194.153.172.13 https://wpadsrv.group.global
#testssl.sh -U --jsonfile-pretty /tmp/prova3.json https://194.153.172.13 

class TestsslVulnerability(object):
    cmd=TESTSSL_CMD
    script_name=""

    def __call__(self,hostadr,port,**kwargs):
        cmd=[
            "/bin/bash", 
            TESTSSL_CMD,
            "-U",
        ]

        if "servername" in kwargs:
            cmd+=[
                '--ip',
                hostadr
            ]
            target="https://"+kwargs["servername"]
        else:
            target="https://"+hostadr

        if port not in [ 443, '443']:
            target='%s:%s' % (target,port)

        kwargs_c={
            "capture_output": True,
            "timeout": 60
        }

        #print(cmd,kwargs_c)

        with tempfile.TemporaryDirectory() as tmpdirname:
            print('created temporary directory', tmpdirname)
            foutput=os.path.join(tmpdirname,"testssl.json")
            cmd+=[
                '--jsonfile-pretty',
                foutput,
                target
            ]

            print(cmd,kwargs_c)

            compl=subprocess.run(
                cmd,
                **kwargs_c,
            )

            if compl.returncode!=0:
                raise base.CommandError(
                    compl.returncode,
                    compl.stderr,
                    compl.stdout
                )

            with open(foutput) as fd:
                data=json.load(fd)

        # err=compl.stderr.decode()
        # out=compl.stdout.decode()
        # root=defusedxml.ElementTree.fromstring(out)
        # data=self._out_parser(root)
        
        return data

# nmap http
