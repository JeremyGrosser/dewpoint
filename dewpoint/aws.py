import urllib.parse
import urllib.request
import urllib.error
import logging
import time
import json


class OAuth2Handler(urllib.request.BaseHandler):
    def __init__(self,
                 client_id,
                 client_secret,
                 token_url,
                 scope,
                 version,
                 timeout=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.scope = scope
        self.version = version
        self.timeout = timeout
        self.token = None
        self.expires_at = 0.0

    def get_token(self):
        if self.token is not None and time.time() < self.expires_at:
            return self.token

        query = {
            'grant_type': 'client_credentials',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': self.scope,
        }

        if self.version.startswith('2.'):
            query = urllib.parse.urlencode(query).encode('ascii')
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            }
            req = urllib.request.Request(
                url=self.token_url,
                headers=headers,
                data=query
            )
        else:
            query = json.dumps(query).encode('ascii')
            headers = {
                'Content-Type': 'application/json',
            }
            req = urllib.request.Request(
                url=self.token_url,
                headers=headers,
                data=query
            )

        response = urllib.request.urlopen(req)
        self.token = json.loads(response.read())
        self.expires_at = time.time() + float(self.token['expires_in'])
        return self.token

    def http_request(self, req):
        token = self.get_token()
        if self.version.startswith('2.'):
            authz = '{token_type} {access_token}, Version {version}'.format(
                token_type=token['token_type'],
                access_token=token['access_token'],
                version=self.version,
            )
        else:
            authz = 'Bearer {access_token}'.format(
                access_token=token['access_token']
            )
        req.add_header('Authorization', authz)
        req.timeout = self.timeout
        return req

    def https_request(self, req):
        return self.http_request(req)


class AWSClient:
    def __init__(self, auth_handler, endpoint, timeout=None):
        self.opener = urllib.request.build_opener(auth_handler)
        self.endpoint = endpoint
        self.timeout = timeout
        self.request_log = logging.getLogger('dewpoint.aws.request')
        self.response_log = logging.getLogger('dewpoint.aws.response')

    def request(self, method, url, data=None, headers=None):
        url = self.endpoint + url
        if data is not None:
            if method != 'POST':
                url = '%s?%s' % (url, urllib.parse.urlencode(data))
                data = None
        if headers is None:
            headers = {}

        self.request_log.debug('%s %s', method, url)
        for key, value in headers.items():
            self.request_log.debug('%s: %s', key, value)
        if data:
            self.request_log.debug(data)

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

        self.response_log.debug(status)
        for key, value in headers.items():
            self.response_log.debug('%s: %s', key, value)
        if response:
            self.response_log.debug(response)

        return status, headers, response
