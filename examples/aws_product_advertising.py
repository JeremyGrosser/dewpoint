#!/usr/bin/env python3
'''
Amazon Product Advertising API Client
'''
from xml.etree import ElementTree
import urllib.parse
import dewpoint.aws
import sys


def camel_case(name):
    parts = []
    for part in name.split('_'):
        parts.append(part[0].upper() + part[1:])
    return ''.join(parts)


class ProductAdvertising(object):
    def __init__(self, key, secret):
        self.api = dewpoint.aws.AWSClient(
            key=key,
            secret=secret,
            version='2013-08-01')

    def ItemSearch(self, endpoint, associate_tag, **kwargs):
        params = {
            'Service': 'AWSEcommerceService',
            'Operation': 'ItemSearch',
            'ContentType': 'text/xml',
            'AssociateTag': associate_tag,
        }

        for key in kwargs:
            params[camel_case(key)] = kwargs[key]

        query = urllib.parse.urlencode(params)
        url = '%s?%s' % (endpoint, query)
        status, headers, xml = self.api.request('GET', url)

        xml = xml.replace(b' xmlns="http://webservices.amazon.com/AWSECommerceService/2013-08-01"', b'')
        tree = ElementTree.XML(xml)
        return tree

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: %s <access key> <secret key>' % sys.argv[0])
        sys.exit(1)

    access_key = sys.argv[1].encode('ascii')
    secret_key = sys.argv[2].encode('ascii')

    pa = ProductAdvertising(access_key, secret_key)

    # Change the endpoint depending on your country:
    # https://docs.aws.amazon.com/AWSECommerceService/latest/DG/AnatomyOfaRESTRequest.html#EndpointsandWebServices
    xml = pa.ItemSearch(
            endpoint='https://webservices.amazon.com/onca/xml',
            associate_tag='synack-20', 
            search_index='Electronics',
            browse_node='1254762011',
            response_group='ItemAttributes,Offers',
            sort='salesrank',
            item_page=1)
    
    for element in xml.iterfind('Items/Item'):
        asin = element.findtext('ASIN')
        name = element.findtext('ItemAttributes/Title')
        price = float(element.findtext('Offers/Offer/OfferListing/Price/Amount')) / 100.0
        url = element.findtext('DetailPageURL')
        print('%s %s\n$%.02f %s\n' % (asin, name, price, url))
