import urllib.request,urllib.error,urllib.parse
import collections
import http.cookiejar
import os.path
import string
import json
import random
import mimetypes
import time


from . import utility

class TimeHTTPConnection(http.client.HTTPConnection):
    """An http.client.HTTPConnection with added timing. 

    TimeHTTPConnection add an attribute *times* to http.client.HTTPConnection to register four time point:
        times["before request"]
            it is the time point just before calling method request()
        times["after request"]
            it is the time point just after calling method request()
        times["before getresponse"]
            it is the time point just before calling method getresponse()
        times["after getresponse"]
            it is the time point just after calling method getresponse()

    So,   for    example,   times["after   getresponse"]-times["before
    getresponse"] is the time spent in getresponse().

    """

    def __init__(self,*args,**kwargs):
        http.client.HTTPConnection.__init__(self,*args,**kwargs)
        self.times={}

    def request(self,*args,**kwargs):
        self.times["before request"]=time.time()
        ret=http.client.HTTPConnection.request(self,*args,**kwargs)
        self.times["after request"]=time.time()
        return ret

    def getresponse(self,*args,**kwargs):
        self.times["before response"]=time.time()
        ret=http.client.HTTPConnection.getresponse(self,*args,**kwargs)
        self.times["after response"]=time.time()
        ret.times=self.times
        return ret

class TimeHTTPSConnection(http.client.HTTPSConnection):
    """An http.client.HTTPSConnection with added timing. 

    TimeHTTPSConnection add an attribute *times* to http.client.HTTPSConnection to register four time point:
        times["before request"]
            it is the time point just before calling method request()
        times["after request"]
            it is the time point just after calling method request()
        times["before getresponse"]
            it is the time point just before calling method getresponse()
        times["after getresponse"]
            it is the time point just after calling method getresponse()

    So,   for    example,   times["after   getresponse"]-times["before
    getresponse"] is the time spent in getresponse().

    """

    def __init__(self,*args,**kwargs):
        http.client.HTTPSConnection.__init__(self,*args,**kwargs)
        self.times={}

    def request(self,*args,**kwargs):
        self.times["before request"]=time.time()
        ret=http.client.HTTPSConnection.request(self,*args,**kwargs)
        self.times["after request"]=time.time()
        return ret

    def getresponse(self,*args,**kwargs):
        self.times["before response"]=time.time()
        ret=http.client.HTTPSConnection.getresponse(self,*args,**kwargs)
        self.times["after response"]=time.time()
        ret.times=self.times
        return ret

class TimeHTTPHandler(urllib.request.HTTPHandler):
    """An urllib.request.HTTPHandler with added timing. 

    It uses TimeHTTPConnection instead of http.client.HTTPConnection."""

    def __init__(self,*args,**kwargs):
        urllib.request.HTTPHandler.__init__(self,*args,**kwargs)

    def http_open(self, req):
        return self.do_open(TimeHTTPConnection, req)

class TimeHTTPSHandler(urllib.request.HTTPSHandler):
    """An urllib.request.HTTPSHandler with added timing. 

    It uses TimeHTTPSConnection instead of http.client.HTTPSConnection."""

    def __init__(self,*args,**kwargs):
        urllib.request.HTTPSHandler.__init__(self,*args,**kwargs)

    def https_open(self, req):
        return self.do_open(TimeHTTPSConnection, req,
                            context=self._context, check_hostname=self._check_hostname)

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Return a Request or None in response to a redirect.

        This is called by the http_error_30x methods when a
        redirection response is received.  If a redirection should
        take place, return a new Request to allow http_error_30x to
        perform the redirect.  Otherwise, raise HTTPError if no-one
        else should try to handle this url.  Return None if you can't
        but another Handler might.
        """
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


class CookieRedirectHandler(urllib.request.HTTPRedirectHandler):
    """An urllib.request.HTTPRedirectHandler able to save and pass cookies through the redirect. 
    """

    def __init__(self,navigator,*args,**kwargs):
        self._navigator=navigator
        urllib.request.HTTPRedirectHandler.__init__(self,*args,**kwargs)

    def _clean_new_url(self,request,newurl):
        u=[ ord(i) for i in newurl ]
        newurl=bytes(u).decode("utf-8")

        urlparts = urllib.parse.urlparse(newurl)

        # For security reasons we don't allow redirection to anything other
        # than http, https or ftp.

        if urlparts.scheme not in ('http', 'https', 'ftp', ''):
            raise HTTPError(
                newurl, code,
                "%s - Redirection to url '%s' is not allowed" % (msg, newurl),
                headers, fp)

        if not urlparts.path and urlparts.netloc:
            urlparts = list(urlparts)
            urlparts[2] = "/"
        newurl = urllib.parse.urlunparse(urlparts)

        # http.client.parse_headers() decodes as ISO-8859-1. Recover the
        # original bytes and percent-encode non-ASCII bytes, and any special
        # characters such as the space.
        newurl = utility.clean_url(newurl)
        newurl = urllib.parse.urljoin(request.full_url, newurl)
        return newurl

    def redirect_request(self,req, fp, code, msg, hdrs, newurl):
        self._navigator.update_cookies(fp,req)
        newurl=self._clean_new_url(req,newurl)
        req=urllib.request.HTTPRedirectHandler.redirect_request(self,req, fp, code, msg, hdrs, newurl)
        self._navigator.add_cookies_to_request(req)
        return req

class ProxyExcludeHandler(urllib.request.ProxyHandler):
    def __init__(self, proxies=None, exclude=None):
        urllib.request.ProxyHandler.__init__(self,proxies=proxies)
        if exclude is None:
            self._exclude=[]
        elif type(exclude) is list:
            self._exclude=exclude
        elif type(exclude) is tuple:
            self._exclude=list(exclude)
        elif exclude=="":
            self._exclude=[]
        else:
            self._exclude=[ x.strip() for x in exclude.split(",") ]

    def _bypass(self,host):
        if "*" in self._exclude: return True
        if host in self._exclude: return True
        hostonly, port = urllib.parse.splitport(host)
        return hostonly in self._exclude
        
    def proxy_open(self, req, *args):
        if req.host and self._bypass(req.host):
            return None
        return urllib.request.ProxyHandler.proxy_open(self,req,*args)

class JwtRedirectHandler(urllib.request.HTTPRedirectHandler):

    def __init__(self,navigator,*args,**kwargs):
        self._navigator=navigator
        urllib.request.HTTPRedirectHandler.__init__(self,*args,**kwargs)

    def _clean_new_url(self,request,newurl):
        u=[ ord(i) for i in newurl ]
        newurl=bytes(u).decode("utf-8")

        urlparts = urllib.parse.urlparse(newurl)

        # For security reasons we don't allow redirection to anything other
        # than http, https or ftp.

        if urlparts.scheme not in ('http', 'https', 'ftp', ''):
            raise HTTPError(
                newurl, code,
                "%s - Redirection to url '%s' is not allowed" % (msg, newurl),
                headers, fp)

        if not urlparts.path and urlparts.netloc:
            urlparts = list(urlparts)
            urlparts[2] = "/"
        newurl = urllib.parse.urlunparse(urlparts)
 
        # http.client.parse_headers() decodes as ISO-8859-1. Recover the
        # original bytes and percent-encode non-ASCII bytes, and any special
        # characters such as the space.
        newurl = utility.clean_url(newurl)
        newurl = urllib.parse.urljoin(request.full_url, newurl)
        return newurl

    def redirect_request(self,req, fp, code, msg, hdrs, newurl):
        newurl=self._clean_new_url(req,newurl)
        req=self._navigator.reset_jwt(req)
        req=urllib.request.HTTPRedirectHandler.redirect_request(self,req, fp, code, msg, hdrs, newurl)
        return req
