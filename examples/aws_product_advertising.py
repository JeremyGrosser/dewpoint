#!/usr/bin/env python3
'''
Amazon Product Advertising API Client
'''
import json
import sys

import dewpoint.aws


def camel_case(name):
    parts = []
    for part in name.split('_'):
        parts.append(part[0].upper() + part[1:])
    return ''.join(parts)


class ProductAdvertising:
    def __init__(self, key, secret):
        auth_handler = dewpoint.aws.AWSAuthHandlerV4(key, secret, 'us-east-1', 'ProductAdvertisingAPI')
        self.api = dewpoint.aws.AWSClient(auth_handler, 'https://webservices.amazon.com')

    def search_items(self, **kwargs):
        params = {}
        for key in kwargs:
            params[camel_case(key)] = kwargs[key]
        payload = json.dumps(params).encode('utf8')

        headers = {
            'content-type': 'application/json; charset=utf-8',
            'content-encoding': 'amz-1.0',
            'x-amz-target': 'com.amazon.paapi5.v1.ProductAdvertisingAPIv1.SearchItems',
        }

        status, headers, response = self.api.request('POST', '/paapi5/searchitems', data=payload, headers=headers)
        return response


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: %s <access key> <secret key>' % sys.argv[0])
        sys.exit(1)

    access_key = sys.argv[1]
    secret_key = sys.argv[2]

    pa = ProductAdvertising(access_key, secret_key)

    data = pa.search_items(
        marketplace='www.amazon.com',
        partner_tag='synack-20',
        partner_type='Associates',
        keywords='harry potter',
        search_index='All',
        resources=['ItemInfo.Title'])

    print(json.dumps(data, indent=2))
