from xml.etree import ElementTree
import urlparse
import urllib2
import urllib

import hashlib
import base64
import hmac
import time
import re

def format_time(ts=None):
    if ts is None:
        ts = time.time()
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ts))


def parse_time(ts):
    ts = int(time.mktime(time.strptime(ts, '%Y-%m-%dT%H:%M:%SZ')))
    return ts


def dictwalk(element):
    '''
    Convenience function for recursively converting a simple XML tree into
    nested dicts
    '''
    children = list(element)
    if not children:
        return {element.tag: element.text}
    else:
        return {element.tag: [dictwalk(x) for x in children]}


class AWSException(Exception):
    def __init__(self, type, code, value, requestid):
        self.type = type
        self.code = code
        self.value = value
        self.requestid = requestid

    def __str__(self):
        return ': '.join((self.code, self.value))

    def __repr__(self):
        return '%s("%s", "%s", "%s", "%s")' % (
            self.__class__.__name__,
            self.type,
            self.code,
            self.value,
            self.requestid,
        )


class AWSAuthHandler(urllib2.BaseHandler):
    def __init__(self, key, secret, version='2010-11-15', timeout=None):
        self.key = key
        self.secret = secret
        self.version = version
        self.timeout = timeout

    def get_signature(self, method, host, uri, query):
        signature_base = '\n'.join((method, host, uri, query))
        signature = hmac.new(self.secret, signature_base, hashlib.sha256)
        signature = urllib.quote(base64.b64encode(signature.digest()))
        return signature

    def parse_uri(self, req):
        method = req.get_method()
        if method == 'POST':
            query = req.get_data()
            uri = req.get_selector()
        else:
            s = req.get_selector()
            if s.find('?') != -1:
                uri, query = s.split('?', 1)
            else:
                uri = s
                query = ''
        return method, uri, query

    def http_request(self, req):
        if not 'Host' in req.headers:
            req.add_header('Host', req.get_host())
        host = req.headers['Host'].lower()
        method, uri, query = self.parse_uri(req)

        query = urlparse.parse_qsl(query)
        query += [
            ('SignatureVersion', '2'),
            ('SignatureMethod', 'HmacSHA256'),
            ('AWSAccessKeyId', self.key),
            ('Version', self.version),
            ('Timestamp', format_time()),
        ]
        query.sort(key=lambda x: x[0])
        query = urllib.urlencode(query)

        signature = self.get_signature(method, host, uri, query)
        query += '&Signature=' + signature

        if method == 'POST':
            req = urllib2.Request(
                req.get_full_url(),
                data=query,
                headers=req.headers)
        else:
            req = urllib2.Request(
                '%s?%s' % (req.get_full_url().split('?', 1)[0], query),
                headers=req.headers)

        req.timeout = self.timeout
        return req

    def https_request(self, req):
        return self.http_request(req)


class AWSClient(object):
    def __init__(self, key, secret, version, endpoint=''):
        self.opener = urllib2.build_opener(AWSAuthHandler(key, secret, version=version))
        self.endpoint = endpoint

    def request(self, method, url, data=None, headers={}):
        url = self.endpoint + url
        if data is not None:
            if method == 'POST':
                data = urllib.urlencode(data)
            else:
                url = '%s?%s' % (url, urllib.urlencode(data))
                data = None

        req = urllib2.Request(url, data, headers)
        try:
            resp = self.opener.open(req)
        except urllib2.HTTPError, e:
            raise self.parse_httperror(e)

        i = resp.info()
        return (resp.code, resp.headers, resp.read())

    def parse_httperror(self, e):
        response = e.fp.read()
        tree = ElementTree.fromstring(response)
        ns = tree.tag.split('}', 1)[0] + '}'
        error = tree.find(ns + 'Error')
        type = error.findtext(ns + 'Type')
        code = error.findtext(ns + 'Code')
        value = error.findtext(ns + 'Message')
        requestid = tree.findtext(ns + 'RequestId')
        return AWSException(type, code, value, requestid)


class AWSProxy(object):
    def __init__(self, *args, **kwargs):
        self.api = AWSClient(*args, **kwargs)

    def _request(self, **kwargs):
        params = {}
        for key, value in kwargs.iteritems():
            if isinstance(value, list):
                for i, v in enumerate(value, 1):
                    params['%s.member.%i' % (key, i)] = v
                continue
            if isinstance(value, dict):
                for i, kv in enumerate(value.iteritems(), 1):
                    k, v = kv
                    params['%s.member.%i.Name' % (key, i)] = k
                    params['%s.member.%i.Value' % (key, i)] = v
                continue
            params[key] = value

        status, headers, response = self.api.request('GET', '/', params)
        return self._parse_xml(response)

    def _parse_xml(self, xml):
        xml = re.sub(' xmlns=".*"', '', xml)
        xml = ElementTree.XML(xml)
        return xml

    def __getattr__(self, name):
        def func(**kwargs):
            kwargs['Action'] = name
            return self._request(**kwargs)
        return func
