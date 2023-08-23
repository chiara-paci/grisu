import urllib
import string

def clean_url(url):
    """ Clean the url, encoded in utf-8, escaping special characters (except punctuation)"""
    encoding="utf-8"
    url = urllib.parse.quote(url, encoding=encoding, safe=string.punctuation)
    return url
