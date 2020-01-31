import urllib.parse
import urllib.request
import urllib.error

import hashlib
import hmac
import time
import json


def format_time(ts):
    return time.strftime('%Y%m%dT%H%M%SZ', ts)


def format_date(ts):
    return time.strftime('%Y%m%d', ts)


def parse_uri(req):
    method = req.get_method()
    if method == b'POST':
        query = req.data
        uri = req.selector
    else:
        s = req.selector
        if s.find('?') != -1:
            uri, query = s.split('?', 1)
        else:
            uri = s
            query = ''
    return method, uri, query


def canonical_headers(req):
    keys = []
    headers = []
    for key, value in sorted(req.headers.items()):
        key = key.strip().lower()
        value = value.strip()
        headers.append('%s:%s' % (key, value))
        keys.append(key)
    canon = '\n'.join(headers) + '\n\n' + ';'.join(keys)
    return canon


def canonical_hash(req):
    method, uri, query = parse_uri(req)

    query = urllib.parse.parse_qsl(query)
    query.sort(key=lambda x: x[0])
    query = urllib.parse.urlencode(query)

    headers = canonical_headers(req)

    if req.data is not None:
        payload = req.data
    else:
        payload = b''

    canon = '{method}\n{uri}\n{query}\n{headers}\n'.format(
        method=method,
        uri=uri,
        query=query,
        headers=headers)
    canon += hashlib.sha256(payload).hexdigest()
    return hashlib.sha256(canon.encode('utf8')).hexdigest()


class AWSAuthHandlerV4(urllib.request.BaseHandler):
    def __init__(self, key, secret, region, service, timeout=None):
        self.key = key
        self.secret = secret
        self.region = region
        self.service = service
        self.timeout = timeout



    def signing_key(self, scope):
        key = b'AWS4' + self.secret.encode('utf8')
        for msg in scope.split('/'):
            key = hmac.digest(key, msg.encode('utf8'), hashlib.sha256)
        return key

    def sign(self, req):
        canon_hash = canonical_hash(req)
        scope = '{date}/{region}/{service}/aws4_request'.format(
            date=format_date(req.timestamp),
            region=self.region,
            service=self.service)

        signing_key = self.signing_key(scope)

        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256',
            format_time(req.timestamp),
            scope,
            canon_hash,
        ])
        string_to_sign = string_to_sign.encode('utf8')
        signature = hmac.digest(signing_key, string_to_sign, hashlib.sha256)

        req.add_header('Authorization', 'AWS4-HMAC-SHA256 Credential={key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}'.format(
            key=self.key,
            scope=scope,
            signed_headers=canonical_headers(req).rsplit('\n', 1)[1],
            signature=signature.hex()))

    def http_request(self, req):
        req.timestamp = time.gmtime(time.time())
        if 'Host' not in req.headers:
            req.add_header('Host', req.host)
        if 'x-amz-date' not in req.headers:
            req.add_header('x-amz-date', format_time(req.timestamp))

        self.sign(req)

        req.timeout = self.timeout
        return req

    def https_request(self, req):
        return self.http_request(req)


class AWSClient:
    def __init__(self, auth_handler, endpoint, timeout=None):
        self.opener = urllib.request.build_opener(auth_handler)
        self.endpoint = endpoint
        self.timeout = timeout

    def request(self, method, url, data=None, headers=None):
        url = self.endpoint + url
        if data is not None:
            if method != 'POST':
                url = '%s?%s' % (url, urllib.parse.urlencode(data))
                data = None
        if headers is None:
            headers = {}

        req = urllib.request.Request(url, data, headers, method=method)

        try:
            resp = self.opener.open(req, timeout=self.timeout)
            status = resp.code
            headers = resp.headers
            response = resp.read()
        except urllib.error.HTTPError as e:
            status = e.code
            headers = e.headers
            response = e.fp.read()

        return status, headers, response
