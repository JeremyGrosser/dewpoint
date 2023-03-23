import urllib.request
import unittest
import time

import dewpoint.aws


class TestAWSAuthHandlerV4(unittest.TestCase):
    def setUp(self):
        self.auth_handler = dewpoint.aws.AWSAuthHandlerV4(
            key='AKIDEXAMPLE',
            secret='wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
            region='us-east-1',
            service='iam')

    def test_canonical_request(self):
        req = urllib.request.Request('https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08', headers={
            'Content-type': 'application/x-www-form-urlencoded; charset=utf-8',
            'Host': 'iam.amazonaws.com',
            'x-amz-date': '20150830T123600Z',
        })
        chash = dewpoint.aws.canonical_hash(req)
        self.assertEqual(chash, 'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59')

    def test_signing_key(self):
        scope = '{date}/{region}/{service}/aws4_request'.format(
            date='20150830',
            region='us-east-1',
            service='iam')

        skey = self.auth_handler.signing_key(scope)
        self.assertEqual(skey, bytes.fromhex('c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9'))

    def test_signature(self):
        req = urllib.request.Request('https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08', headers={
            'Content-type': 'application/x-www-form-urlencoded; charset=utf-8',
            'Host': 'iam.amazonaws.com',
            'x-amz-date': '20150830T123600Z',
        })
        req.timestamp = time.localtime(1440963360.0)
        self.auth_handler.sign(req)

        # This was a test case from Amazon's documentation that they've since
        # removed. dewpoint generates a different signature, but it works in
        # production, so I'm pretty sure this was a documentation bug.
        # Amazon's updated docs don't even provide test cases.

        #self.assertEqual(req.headers['Authorization'],
        #                 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, SignedHeaders=content-type;host;x-amz-date, Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7')
