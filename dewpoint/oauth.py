from collections import namedtuple
import urlparse
import urllib2
import urllib
import random
import hashlib
import base64
import hmac
import time

Consumer = namedtuple('Consumer', 'key secret')
Token = namedtuple('Token', 'key secret')

alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'


class Request(urllib2.Request):
    def __init__(self, url, data=None, headers={},
                 origin_req_host=None, unverifiable=False, method=None,
                 oauth_params={}):
        urllib2.Request.__init__(self, url, data, headers, origin_req_host,
                                 unverifiable)
        self.method = method
        self.oauth_params = oauth_params

    def get_method(self):
        if self.method is not None:
            return self.method
        if self.has_data():
            return 'POST'
        else:
            return 'GET'


class OAuthHandler(urllib2.BaseHandler):
    def __init__(self, consumer, token=None, timeout=None):
        self.consumer = consumer
        self.token = token
        self.timeout = timeout

    def encode(self, q):
        return '&'.join(['%s=%s' % (k, v) for k, v in q])

    def quote(self, s):
        return urllib.quote(s, '-._~')

    def get_signature(self, method, uri, query):
        key = '%s&' % self.quote(self.consumer.secret)
        if self.token is not None:
            key += self.quote(self.token.secret)

        signature_base = '&'.join((
            method.upper(),
            self.quote(uri),
            self.quote(query)))

        signature = hmac.new(key, signature_base, hashlib.sha1)
        signature = base64.b64encode(signature.digest())
        return signature

    def make_nonce(self, length=16):
        return ''.join([random.choice(alpha) for i in range(length)])

    def parse_uri(self, req):
        method = req.get_method()
        if method == 'POST':
            uri = req.get_selector()
            query = req.get_data()
            if query is None:
                query = ''
        else:
            url = req.get_full_url()
            if url.find('?') != -1:
                uri, query = req.get_full_url().split('?', 1)
            else:
                uri = url
                query = ''
        return method, uri, query

    def http_request(self, req):
        if not 'Host' in req.headers:
            req.add_header('Host', req.get_host())
        method, uri, query = self.parse_uri(req)

        oauth_params = [
            ('oauth_consumer_key', self.consumer.key),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', int(time.time())),
            ('oauth_nonce', self.make_nonce()),
            ('oauth_version', '1.0'),
        ]
        if self.token is not None:
            oauth_params.append(('oauth_token', self.token.key))
        if hasattr(req, 'oauth_params'):
            oauth_params += req.oauth_params.items()

        query = urlparse.parse_qsl(query)
        if 'Content-type' in req.headers and \
            req.headers['Content-type'] == 'application/x-www-form-urlencoded':
            query += urlparse.parse_qsl(req.data)
        query += oauth_params
        query.sort(key=lambda x: x[0])

        signature = self.get_signature(method, uri, self.encode(query))
        query.append(('oauth_signature', self.quote(signature)))

        query.sort()
        auth = ', '.join(['%s="%s"' % (k, v) for k, v in query])
        req.headers['Authorization'] = 'OAuth ' + auth

        if method == 'POST':
            req = Request(req.get_full_url(), data=req.get_data(),
                          headers=req.headers,
                          origin_req_host=req.origin_req_host,
                          unverifiable=req.unverifiable,
                          method=method)
        else:
            url = req.get_full_url()
            req = Request(url, data=req.data, headers=req.headers,
                          origin_req_host=req.origin_req_host,
                          unverifiable=req.unverifiable,
                          method=method)

        req.timeout = self.timeout
        return req

    def https_request(self, req):
        return self.http_request(req)
