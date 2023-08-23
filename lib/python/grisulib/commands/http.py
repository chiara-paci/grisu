from . import base

from weblib import navigator
import ssl
import platform

class HttpHeaders(object):
    def __call__(self,url,proxy=None):
        ssl_context=ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode=ssl.CERT_NONE

        if proxy is None:
            nav=navigator.NoRedirectNavigator(None,ssl_context=ssl_context)
        else:
            nav=navigator.NoRedirectNavigator(None,ssl_context=ssl_context,proxy=proxy)
            
        print(url)
        response=nav.get(url)

        ret={
            "status": response.status,
            "reason": response.reason,
            "headers": response.headers,
            "request": {
                "url": url,
                "method": "GET",
                "ssl_context": {
                    "verify_mode": "ssl.CERT_NONE",
                    "check_hostname": False,
                },
                "client": {
                    "user_agent": nav.user_agent,
                    "timeout": nav._timeout,
                    "encoding": nav.encoding,
                    "python_version": platform.python_version(),
                }
            },
        }

        # servisse capire se e quale proxy viene usato, bisogna scorrere nav._opener.handlers
        # e trovare un figlio di urllib.request.ProxyHandler, che ha un attributo proxies;
        # nel caso fosse un weblib.handlers.ProxyExcludeHandler ha anche un attributo _exclude
        # che implementa il no_proxy; ovviamente va creato un metodo di Navigator

        return ret
