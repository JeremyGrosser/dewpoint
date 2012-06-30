'''
NAME
dewpoint.oauth

DESCRIPTION
This module provides a urllib2 compatible opener for signing requests as
defined by the OAuth 1.0a specification. Only the HMAC-SHA1 signature method
is currently supported.

EXAMPLE
>>> # Basic example using a static consumer token:
>>> from oauth import OAuthHandler, Token, Consumer
>>> import urllib2
>>> opener = urllib2.build_opener(OAuthHandler(Consumer('xxxxxx', 'supersecret')))
>>> urllib2.install_opener(opener)
>>> response = urllib2.urlopen('http://api.example.com/1.0/magic')
>>> print response.read()

LICENSE
New BSD License

Copyright (c) 2011, Jeremy Grosser
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
Neither the name of Jeremy Grosser nor the names of its contributors may be
used to endorse or promote products derived from this software without
specific prior written permission.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
'''

from collections import namedtuple
import urlparse
import urllib2
import urllib
import random
import hashlib
import base64
import hmac
import time

__all__ = ['OAuthHandler', 'Consumer', 'Token', 'Request']

def encode(params):
    '''urlencode a set of parameters as specified in the OAuth 1.0a spec'''
    return '&'.join(['%s=%s' % (k, v) for k, v in params])


def quote(text):
    '''Quote the given text as specified by the OAuth 1.0a spec'''
    return urllib.quote(text, '-._~')


def make_nonce(length=16):
    '''Generate a random ASCII alphanumeric string'''
    alpha = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    return ''.join([random.choice(alpha) for i in range(length)])


def parse_uri(req):
    '''
    Returns a normalized (method, uri, query) tuple for the given request,
    taking into account POST data and GET query arguments.
    '''
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

Consumer = namedtuple('Consumer', 'key secret')
Token = namedtuple('Token', 'key secret')


class Request(urllib2.Request):
    '''
    This subclass adds "method" and "oauth_params" arguments to
    urllib2.Request, allowing more fine-grained control of the OAuth process
    and HTTP request.
    '''
    def __init__(self, url, data=None, headers={}, origin_req_host=None,
                 unverifiable=False, method=None, oauth_params=None):
        urllib2.Request.__init__(self, url, data, headers, origin_req_host,
                                 unverifiable)
        if headers is None:
            self.headers = {}
        if oauth_params is None:
            oauth_params = {}
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
    '''
    Drop-in handler for urllib2 that signs all requests using the given OAuth
    consumer credentials. An optional token may be provided. This is usually
    an access or request token provided by the target API during the three
    legged authentication procedure.

    This opener will work with any standard urllib2.Request instance, but
    allows a custom oauth_params dict to be populated if using the Request
    subclass included in this module.
    '''
    def __init__(self, consumer, token=None, timeout=None):
        self.consumer = consumer
        self.token = token
        self.timeout = timeout

    def get_signature(self, method, uri, query):
        '''
        Returns an HMAC-SHA1 signature for the given parameters using
        self.consumer and self.token as the secrets.
        '''
        key = '%s&' % quote(self.consumer.secret)
        if self.token is not None:
            key += quote(self.token.secret)

        signature_base = '&'.join((
            method.upper(),
            quote(uri),
            quote(query)))

        signature = hmac.new(str(key), signature_base, hashlib.sha1)
        signature = base64.b64encode(signature.digest())
        return signature

    def http_request(self, req):
        '''
        Signs the given HTTP request as specified by the OAuth 1.0a
        specification.
        '''
        if not 'Host' in req.headers:
            req.add_header('Host', req.get_host())
        method, uri, query = parse_uri(req)

        oauth_params = [
            ('oauth_consumer_key', self.consumer.key),
            ('oauth_signature_method', 'HMAC-SHA1'),
            ('oauth_timestamp', int(time.time())),
            ('oauth_nonce', make_nonce()),
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

        signature = self.get_signature(method, uri, encode(query))
        query.append(('oauth_signature', quote(signature)))

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
        '''
        Wrapper around OAuthHandler.http_request. OAuth signing is
        functionally the same for both HTTP and HTTPS transports.
        '''
        return self.http_request(req)
