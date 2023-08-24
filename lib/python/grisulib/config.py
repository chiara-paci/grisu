import os

class _Config(object):
    DEFAULT_PORT = 443
    
    def __init__(self):
        self._basedir=os.path.dirname( # B
            os.path.dirname( # B/lib
                os.path.dirname( # B/lib/python
                    os.path.dirname(os.path.abspath(__file__)) # B/lib/python/grisulib
                )
            )
        )
        self._userdir=os.path.join(os.path.expanduser("~"),".grisu")

        os.makedirs(self._userdir,mode=0o700,exist_ok=True)
        
        self._defaults={
            "cmd_paths": {
                "nmap":    "/usr/bin/nmap",
                "sudo":    "/usr/bin/sudo",
                "timeout": "/usr/bin/timeout",
                "openssl": "/usr/bin/openssl",
                "openvas": "/usr/bin/openvas-nasl",
                "testssl": "/usr/bin/testssl",
            },
            "plugins_paths": {
                "nasl":[
                    "/var/lib/openvas/plugins",
                    os.path.join(self._basedir,"lib","plugins","nasl"),
                ]
            },
            
        }

        with open(os.path.join(self._basedir,"VERSION")) as fd:
            self.VERSION=fd.read().strip()

    def set_options(self,options): pass

Config=_Config()
