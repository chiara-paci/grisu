""" Rich web client.
"""

import urllib.request,urllib.error,urllib.parse
import collections
import http.cookiejar
import os.path
import string
import json
import random
import mimetypes
import time
import base64

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from . import handlers as basehandlers
from . import utility

class ConnectionError(Exception):
    def __init__(self,response):
        self.response=response

    def __str__(self):
        return "Connection Error on url %s" % self.response.url

class ErrorPageException(Exception):
    def __init__(self,response):
        self.response=response

    def __str__(self):
        return "Page Error on url %s" % self.response.url

class ResponseHeaders(collections.OrderedDict): pass

class Response(object):
    """Object representing an http response. 

    It is  build or with  an HTTPResponse  returned by the  opener, or
    with the exception raised in opening.

    Attributes:

        *fresponse* 
            The wrapped http response or exception.
        *request*
            The request.
        *url*
            The url requested.
        *status*
            Status of the response (numeric). It could be:
            * An http error code, if available
            * 601, if the exception is urllib.error.URLError
            * 700 otherwise
        *reason*
            The message corresponding to status.
        *text*
            The body of response,  if available.  If decode_text=True,
            then the  body is encoded  in utf-8.  Else, it is  the raw
            body.

    """

    def __init__(self,fresponse,request=None,decode_text=True):
        self.fresponse=fresponse
        self.request=request
        self.url=self._url(fresponse,request)
        self.status,self.reason,self.text,headers=self._data(fresponse,request,decode_text)
        self._set_headers(headers)

    def _url(self,fresponse,request):
        url=fresponse.geturl()
        if url: return url
        # if request is None:
        #     return fresponse.geturl()
        return request.full_url
        
    def _data(self,fresponse,request,decode_text):
        if (not isinstance(fresponse,Exception)) or (isinstance(fresponse,urllib.error.HTTPError)): 
            status=fresponse.status
            reason=fresponse.reason
            headers=fresponse.getheaders()

            btext=fresponse.read()
            d=fresponse.read()
            while d:
                btext+=d
                d=fresponse.read()
            if decode_text:
                #text=fresponse.read().decode('utf-8')
                text=btext.decode("utf-8")
            else:
                #text=fresponse.read()
                text=btext
        else:
            headers=[]
            text=""
            status,reason=self._process_error(fresponse)
        return status,reason,text,headers

    def _process_error(self,error):
        if isinstance(error,urllib.error.URLError):
            msg="%s: %s", (str(error),str(error.reason))
            return 601,msg
        return 700,str(error)

    def __str__(self):
        return "%s %s %s" % (self.status,self.reason,self.url)

    def _set_headers(self,headers):
        self.headers=ResponseHeaders()
        for key,val in headers:
            if key not in self.headers.keys():
                self.headers[key]=val
                continue
            if type(self.headers[key])==list:
                self.headers[key].append(val)
                continue
            self.headers[key]=[ self.headers[key],val ]


class Navigator(object):
    """Navigator emulates browser behaviour. 
    
    You  can have  as  many *navigators*  as you  want,  each with  its
    environment, emulating multiple users.

    *cookiefile*  

         The file  path for  storing cookies.   If it  doesn't exists,
         navigator will  create it.  If  it exists, it will  be reused
         through navigations. Two navigators using the same cookiefile
         belong  for  several  aspects  to  the  same  user,  so  it's
         important to use separate cookiefiles to insulate navigations.

         If cookiefile is  empty or None, cookies will not be managed.

    *ssl_context*

         This  is an  ssl.SSLContext object  describing how  to handle
         ssl. If missed, default HTTPSHandler behaviour is used.

    *add_handlers*
         
         List of HTTPHandler to add to the underling opener.

    Attributes:
         *url*
              Last url requested.
         *time_http*
              The TimeHTTPHandler handling http requests.
         *time_https*
              The TimeHTTPSHandler handling https requests.

    """

    encoding="utf-8"
    _timeout=600
    """Timeout of requests."""
    user_agent="Weblib"

    headers=[]

    def __init__(self,cookiefile,cookiepolicy=None,
                 proxy={
                     "type": "environment",
                     "exclude": None
                 },
                 ssl_context=None,
                 **hargs):
        self.url=""
        self._cookiejar=None
        handlers=self._mk_handlers(cookiefile,cookiepolicy=cookiepolicy,
                                   proxy=proxy,ssl_context=ssl_context,
                                   **hargs)
        self._opener=urllib.request.build_opener(*handlers)

    def _mk_handlers(self,cookiefile,cookiepolicy=None,
                     proxy={
                         "type": "environment",
                         "exclude": None
                     },
                     ssl_context=None,
                     **kwargs):
        handlers=[]

        print("H",proxy)

        handlers.append(urllib.request.HTTPHandler)

        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))

        if not cookiefile:
            handlers.append(self._proxy_support(proxy))
            return handlers

        if not os.path.isfile(cookiefile):
            dname=os.path.dirname(cookiefile)
            os.makedirs(dname, exist_ok=True)
            fd=open(cookiefile,'w')
            fd.write('#LWP-Cookies-2.0\n')
            fd.close()
        if cookiepolicy not in kwargs or kwargs["cookiepolicy"] is None:
            self._cookiejar=http.cookiejar.LWPCookieJar(cookiefile)
        else:
            self._cookiejar=http.cookiejar.LWPCookieJar(cookiefile,
                                                        policy=kwargs["cookiepolicy"])
        self._cookiejar.load(ignore_discard=True,ignore_expires=True)
        handlers.append(basehandlers.CookieRedirectHandler(self))
        handlers.append(self._proxy_support(proxy))
        return handlers

    def _proxy_support(self,proxy):
        if proxy["type"]=="no proxy":
            return basehandlers.ProxyExcludeHandler({})

        if proxy["type"]=="environment":
            proxies=urllib.request.getproxies()
            return basehandlers.ProxyExcludeHandler(proxies=proxies,
                                                    exclude=proxy["exclude"])
        # non va, bisogna agire a livello socket
        #if proxy["type"]=="socks5":
        #    url="socks5://%(host)s:%(port)d" % proxy
        if proxy["type"]=="authenticate":
            url="http://%(username)s:%(password)s@%(host)s:%(port)d" % proxy
        else:
            url="http://%(host)s:%(port)d" % proxy
 
        proxies={ "http": url , "https": url }
        return basehandlers.ProxyExcludeHandler(proxies=proxies,
                                                exclude=proxy["exclude"])
        
    def has_cookie(self,name):
        for cookie in self._cookiejar:
            if cookie.is_expired(): continue
            if cookie.name!=name: continue
            #if cookie.value is None:
            #    return cookie.value
            return cookie
        return None

    def print_cookies(self):
        """ Print all cookies in the navigator. """
        print("Cookies:")
        for cookie in self._cookiejar:
            print(cookie.name,cookie.value,cookie.domain,cookie.port,
                  cookie.path,cookie.expires,cookie.is_expired())


    def add_cookie(self,name,value,version=0,port=None,
                   domain=None, path=None, secure=False, expires=None, is_session=False, 
                   comment=None, comment_url=None, non_standard={}):
        """Add a cookie to the navigator.

        *version* (int or None). 
            Netscape cookies  have version  0 (the default).  RFC 2965
            and RFC 2109 cookies have a version cookie-attribute of 1.
        *name* (str)
            Cookie name (a string).
        *value* (str)
            Cookie value or None.
        *port* (str)
            Cookie port or a set of ports (eg. '80', or '80,8080'), or None.
        *path* (str)
            Cookie path (a string, eg. '/acme/rocket_launchers').
        *secure* (boolean)
            True if cookie should only be returned over a secure connection.
        *expires* (int)
            Integer expiry date in seconds since epoch, or None.
        *is_session* (boolean)
            True if this is a session cookie.
        *comment* (str)
            String comment from the server explaining the function of this cookie, or None.
        *comment_url* (str)
            URL linking to a comment from the server explaining the function of this cookie, or None.
        *non_standard* (dict)
            Dictionary of non standard attributes to set.

        """

        if self._cookiejar is None: return
        port_specified=False
        domain_specified=False
        path_specified=False
        domain_initial_dot=False 
        
        if port is not None: port_specified=True
        if domain is not None: 
            domain_specified=True
            if domain.startswith("."): domain_initial_dot=True 
        if path is not None: path_specified=True

        self._cookiejar.set_cookie(http.cookiejar.Cookie(version, name, value, port, port_specified, 
                                                         domain,domain_specified, domain_initial_dot, 
                                                         path, path_specified,
                                                         secure, expires, is_session, 
                                                         comment, comment_url,
                                                         non_standard)) 
        self._cookiejar.save(ignore_discard=True,ignore_expires=True)

    def add_cookies_to_request(self,request):
        """ Add a cookie to a request. """

        if self._cookiejar is None: return
        self._cookiejar.add_cookie_header(request)

    def update_cookies(self,response,request):
        """ Update cookies after a browser/server interaction. """

        if self._cookiejar is None: return
        self._cookiejar.extract_cookies(response,request)
        self._cookiejar.save(ignore_discard=True,ignore_expires=True)
        #self.print_cookies()

    def get_cookie(self,name):
        for cookie in self._cookiejar:
            if cookie.name==name: return cookie
        return None

    def get_cookies(self):
        return { cookie.name: cookie for cookie in self._cookiejar }

    def clear_cookies(self):
        self._cookiejar.clear()

    # fields={ name: value, name: value }
    # files={
    #     name: {
    #         "filename": filename,
    #         "mimetype": mimetype, (optional)
    #         "content":  content,
    #     },
    #     ...
    # }
    def _encode_data(self, fields, files, as_json=False,force_multipart=False):
        def escape_quote(s):
            return s.replace('"', '\\"')

        headers={}

        if not force_multipart and not files:
            if as_json: 
                body=json.dumps(fields)
                headers['Content-Type']="application/json"
            else:
                body=urllib.parse.urlencode(fields)
            body=body.encode()
            return body,headers.items()

        boundary = ''.join(random.choice(string.digits + string.ascii_letters) for i in range(30))
        headers['Content-Type']= 'multipart/form-data; boundary='+boundary

        lines = []
        boundary="--"+boundary
        hdr_field_fmt='Content-Disposition: form-data; name="%s"'
        for name, value in fields.items():
            lines+=[
                boundary,
                hdr_field_fmt % escape_quote(name),
                '',
                str(value),
            ]

        hdr_file_fmt1='Content-Disposition: form-data; name="%s"; filename="%s"'
        hdr_file_fmt2='Content-Disposition: form-data; name="%s"'
        mime_file_fmt='Content-Type: %s'
        for name, value in files.items():
            if "filename" in value:
                filename = value['filename']
                hdr=hdr_file_fmt1 % (escape_quote(name), escape_quote(filename))
            else:
                hdr=hdr_file_fmt2 % escape_quote(name)
                
            if 'mimetype' in value:
                mimetype = value['mimetype']
            else:
                mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
            lines+=[
                boundary,
                hdr,
                mime_file_fmt % mimetype,
                '',
                value['content'],
            ]

        lines.append(boundary+"--")
        lines.append("")

        body='\r\n'.join(lines)
        body=body.encode()

        return (body, headers.items())

    def get(self,url,url_params=[],data={},headers=[],decode_text=True):
        """ Perform a GET to the server.

        *url* (str)
             Full url to request.
        *data* (dict)
             Dictionary of data to add to the request.
        *headers* (list of tuple (key,value) )
             Headers to add to the request
        *decode_text* (boolean)
             True if the body of response has to be decoded as utf-8.

        Return a tuple (response,tconn,texec) where:

        *response*
             is a Response object with the response.
        *tconn*
             is the time spent connecting to the server.
        *texec*
             is the time used by the server to create the page.

        *tconn* and *texec* are -1 when the server is unreachable.

        """
        return self._open(url,url_params=url_params,data=data,
                          method="GET",headers=headers,decode_text=decode_text)

    def post(self,url,url_params=[],data={},files={},headers=[],
             decode_text=True,as_json=False,force_multipart=False):
        """Perform a POST to the server.

        *url* (str)
             Full url to request.
        *data* (dict)
             Dictionary of data to add to the request.
        *files* (dict)
             Dictionary of files to add to the request.
        *headers* (list of tuple (key,value) )
             Headers to add to the request
        *decode_text* (boolean)
             True if the body of response has to be decoded as utf-8.
        *as_json* (boolean)
             True if data has to be represented as json in the body of
             the request. False if it has to be represented as string.

        Return a tuple (response,tconn,texec) where:

        *response*
             is a Response object with the response.
        *tconn*
             is the time spent connecting to the server.
        *texec*
             is the time used by the server to create the page.

        *tconn* and *texec* are -1 when the server is unreachable.

        """
        return self._open(url,url_params=url_params,data=data,files=files,method='POST',
                          headers=headers,decode_text=decode_text,as_json=as_json,force_multipart=force_multipart)

    def put(self,url,data={},files={},headers=[],decode_text=True,as_json=False):
        """Perform a PUT to the server.

        *url* (str)
             Full url to request.
        *data* (dict)
             Dictionary of data to add to the request.
        *files* (dict)
             Dictionary of files to add to the request.
        *headers* (list of tuple (key,value) )
             Headers to add to the request
        *decode_text* (boolean)
             True if the body of response has to be decoded as utf-8.
        *as_json* (boolean)
             True if data has to be represented as json in the body of
             the request. False if it has to be represented as string.

        Return a tuple (response,tconn,texec) where:

        *response*
             is a Response object with the response.
        *tconn*
             is the time spent connecting to the server.
        *texec*
             is the time used by the server to create the page.

        *tconn* and *texec* are -1 when the server is unreachable.

        """
        return self._open(url,data=data,files=files,method='PUT',headers=headers,
                          decode_text=decode_text,as_json=as_json)

    def delete(self,url,headers=[],decode_text=True):
        """ Perform a DELETE to the server.

        *url* (str)
             Full url to request.
        *headers* (list of tuple (key,value) )
             Headers to add to the request
        *decode_text* (boolean)
             True if the body of response has to be decoded as utf-8.

        Return a tuple (response,tconn,texec) where:

        *response*
             is a Response object with the response.
        *tconn*
             is the time spent connecting to the server.
        *texec*
             is the time used by the server to create the page.

        *tconn* and *texec* are -1 when the server is unreachable.

        """
        return self._open(url,method='DELETE',headers=headers,decode_text=decode_text)


    def put_upload(self,url,content,content_type="text/plain",headers=[],decode_text=True):
        """Perform an upload (via PUT) to the server.

        *url* (str)
             Full url to request.
        *content* (str or bytes)
             The content to be uploaded.
        *content_type* (str)
             The mime type of the content.
        *headers* (list of tuple (key,value) )
             Headers to add to the request
        *decode_text* (boolean)
             True if the body of response has to be decoded as utf-8.

        Return a tuple (response,tconn,texec) where:

        *response*
             is a Response object with the response.
        *tconn*
             is the time spent connecting to the server.
        *texec*
             is the time used by the server to create the page.

        *tconn* and *texec* are -1 when the server is unreachable.

        """
        return self._upload(url,content,method="PUT",content_type=content_type,
                            headers=headers,decode_text=decode_text)

    def post_upload(self,url,content,content_type="text/plain",headers=[],decode_text=True):

        """Perform an upload (via POST) to the server.

        *url* (str)
             Full url to request.
        *content* (str or bytes)
             The content to be uploaded.
        *content_type* (str)
             The mime type of the content.
        *headers* (list of tuple (key,value) )
             Headers to add to the request
        *decode_text* (boolean)
             True if the body of response has to be decoded as utf-8.

        Return a tuple (response,tconn,texec) where:

        *response*
             is a Response object with the response.
        *tconn*
             is the time spent connecting to the server.
        *texec*
             is the time used by the server to create the page.

        *tconn* and *texec* are -1 when the server is unreachable.

        """

        return self._upload(url,content,content_type=content_type,
                            headers=headers,decode_text=decode_text)

    def _open(self,url,method='GET',url_params=[],data={},files={},
              headers=[],decode_text=True,as_json=False,force_multipart=False):
        url = utility.clean_url(url)

        print("UUU",url)

        if url_params:
            url+='?'+'&'.join( [ k+"="+str(v) for k,v in url_params ] )

        data_headers=[]
        if data or files:
            data,data_headers=self._encode_data(data,files,as_json=as_json,force_multipart=force_multipart)
            request=urllib.request.Request(url=url,data=data,method=method)
        else:
            request=urllib.request.Request(url=url,method=method)

        self.add_cookies_to_request(request)

        for k,v in self.headers:
            request.add_header(k,v)
        if self.user_agent is not None:
            request.add_header("User-agent", self.user_agent)
        for k,v in data_headers:
            request.add_header(k,v)
        for k,v in headers:
            request.add_header(k,v)

        return self._go(request,decode_text)

    def _go(self,request,decode_text):
        try:
            f=self._opener.open(request,timeout=self._timeout)
            response=Response(f,request,decode_text=decode_text)
            self.update_cookies(f,request)
            f.close()
        except urllib.error.HTTPError as e:
            response=Response(e,request)

        self.url=response.url
        return response

    def _upload(self,url,content,method='POST',content_type="text/plain",
                headers=[],decode_text=True):
        url = utility.clean_url(url)

        if type(content) is str:
            data=content.encode()
        else:
            data=content
        data=data.replace(b'\r',b'')
        data=data.replace(b'\n',b'\r\n')
        request=urllib.request.Request(url=url,data=data,method=method)

        self.add_cookies_to_request(request)

        for k,v in self.headers:
            request.add_header(k,v)

        if self.user_agent is not None:
            request.add_header("User-agent", self.user_agent)
        request.add_header("Content-Type", content_type)
        for k,v in headers:
            request.add_header(k,v)

        return self._go(request,decode_text)

class NoRedirectNavigator(Navigator):

    def _mk_handlers(self,*args,**kwargs):
        handlers=Navigator._mk_handlers(self,*args,**kwargs)
        return [ basehandlers.NoRedirectHandler() ] + handlers




class TimeNavigator(Navigator):
    def __init__(self,cookiefile=None,
                 proxy={
                     "type": "environment",
                     "exclude": None
                 },
                 ssl_context=None,
                 add_handlers=[]):
        Navigator.__init__(self,cookiefile,cookiepolicy=None,proxy=proxy,
                           ssl_context=ssl_context,add_handlers=add_handlers)

    def _mk_handlers(self,cookiefile,cookiepolicy=None,
                     proxy={
                         "type": "environment",
                         "exclude": None
                     },
                     ssl_context=None,add_handlers=[]):
        self.time_http=basehandlers.TimeHTTPHandler()
        if ssl_context is None:
            self.time_https=basehandlers.TimeHTTPSHandler()
        else:
            self.time_https=basehandlers.TimeHTTPSHandler(context=ssl_context)

        handlers=[self.time_http,self.time_https]
        handlers+=Navigator._mk_handlers(self,cookiefile,cookiepolicy=cookiepolicy,
                                         proxy=proxy)
        handlers+=add_handlers

        return handlers

    def _go(self,request,decode_text):
        tconn=-1
        texec=-1
        try:
            f=self._opener.open(request,timeout=self._timeout)
            response=Response(f,request,decode_text=decode_text)
            self.update_cookies(f,request)
            if ("before request" in f.times) and ("after request" in f.times):
                tconn=f.times["after request"]-f.times["before request"]
            if ("before response" in f.times) and ("after response" in f.times):
                texec=f.times["after response"]-f.times["before response"]
            f.close()
        except Exception as e:
            response=Response(e,request)
        self.url=response.url
        return response,tconn,texec

class SingleSiteMixin(object):
    def rel_get(self,rel_url,**kwargs):
        """ GET relative to site base url. """
        url=self._base_url+rel_url
        return self.get(url,**kwargs)
        
    def rel_post(self,rel_url,**kwargs):
        """ POST relative to site base url. """
        url=self._base_url+rel_url
        return self.post(url,**kwargs)
        
    def rel_put(self,rel_url,**kwargs):
        """ PUT relative to site base url. """
        url=self._base_url+rel_url
        return self.put(url,**kwargs)

    def rel_put_upload(self,rel_url,**kwargs):
        """ PUT UPLOAD relative to site base url. """
        url=self._base_url+rel_url
        return self.put_upload(url,**kwargs)
        
    def rel_delete(self,rel_url,**kwargs):
        """ DELETE relative to site base url. """
        url=self._base_url+rel_url
        return self.delete(url,**kwargs)

class SingleSiteNavigator(Navigator,SingleSiteMixin):
    """Navigator for single site browsing. 

    *base_url* (str)
        Base url of site.
    *\\*\\*args,\\*\\*kwargs*
        Parameters to `Navigator`.

    Define additional methods to use relative urls in same site.

    """
    
    def __init__(self,base_url,*args,**kwargs):
        Navigator.__init__(self,*args,**kwargs)
        self._base_url=base_url

class JwtNavigator(Navigator):
    def __init__(self,
                 proxy={
                     "type": "environment",
                     "exclude": None 
                 },ssl_context=None):
        Navigator.__init__(self,None,proxy=proxy,ssl_context=ssl_context)
        self._private_key=None
        self._username=None

    def _load_key(self,keydata):
        return serialization.load_ssh_private_key(keydata.encode(),None)

    def _sign(self,token):
        return self._private_key.sign(token)
        #return rsa.sign(token,self._private_key,"SHA-512")

    def _mk_handlers(self,*args,**kwargs):
        return [ basehandlers.JwtRedirectHandler(self) ]

    def set_auth_data(self,username,keydata):
        self._username=username
        if keydata:
            self._private_key=self._load_key(keydata)
        else:
            self._private_key=None

    def reset_jwt(self,req):
        if req.has_header("Authorization"):
            req.remove_header("Authorization")
        jwt=self._add_jwt()
        if jwt:
            key,val=jwt[0]
            req.add_header(key,val)
        return req

    def _add_jwt(self):
        if not self._username or not self._private_key: return []
        header = '{"alg":"HS512","typ":"JWT"}'
        payload = '{"iss":"'+self._username+'","iat":'+str(time.time())+'}'
        token = base64.urlsafe_b64encode(header.encode('utf-8'))
        token+= b'.' + base64.urlsafe_b64encode(payload.encode('utf-8'))
        signature = self._sign(token)
        token += b'.' + base64.urlsafe_b64encode(signature)
        return [ ("Authorization", b"Bearer "+token) ]

    def _open(self,*args,headers=[],**kwargs):
        headers=headers[:]
        headers+=self._add_jwt()
        return Navigator._open(self,*args,headers=headers,**kwargs)

class SingleSiteJwtNavigator(JwtNavigator,SingleSiteMixin):
    
    def __init__(self,base_url,*args,**kwargs):
        JwtNavigator.__init__(self,*args,**kwargs)
        self._base_url=base_url



class RsaJwtNavigator(JwtNavigator):
    def _load_key(self,keydata):
        return rsa.PrivateKey.load_pkcs1(keydata)

    def _sign(self,token):
        return rsa.sign(token,self._private_key,"SHA-512")

class CsrfNavigator(Navigator):
    def _open(self,*args,headers=[],**kwargs):
        headers=headers[:]
        csrftoken=self.get_cookie("csrftoken")
        if csrftoken is not None:
            headers.append( ("X-CSRFToken", csrftoken.value) )
        return Navigator._open(self,*args,headers=headers,**kwargs)

class JwtTokenNavigator(CsrfNavigator):
    def __init__(self,cookiefile,token=None,ssl_context=None):
        CsrfNavigator.__init__(self,cookiefile,ssl_context=ssl_context)
        self.token=token 

    def _mk_handlers(self,*args,**kwargs):
        return [ basehandlers.JwtRedirectHandler(self) ]

    def reset_jwt(self,req):
        return req

    def _open(self,*args,headers=[],**kwargs):
        headers=headers[:]
        if self.token is not None:
            headers+=[
                ("Authorization", b"Bearer "+self.token),
            ]
        return CsrfNavigator._open(self,*args,headers=headers,**kwargs)

class JsonNavigator(Navigator):
    headers=[("Accept","application/json")]
        
class JsonSingleSiteNavigator(SingleSiteNavigator):
    headers=[("Accept","application/json")]

class JsonJwtNavigator(JwtNavigator):
    headers=[("Accept","application/json")]

class JsonCsrfNavigator(CsrfNavigator):
    headers=[("Accept","application/json")]

class JsonJwtTokenNavigator(JwtTokenNavigator):
    headers=[("Accept","application/json")]

