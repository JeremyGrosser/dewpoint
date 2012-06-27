from pprint import pprint
import os

import dewpoint.aws


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


ec2 = dewpoint.aws.AWSProxy(
    key=os.environ['AWS_ACCESS_KEY_ID'],
    secret=os.environ['AWS_SECRET_ACCESS_KEY'],
    version='2012-06-01',
    baseurl='https://ec2.us-east-1.amazonaws.com')


response = ec2.DescribeInstances()
# response is an xml.etree.ElementTree.Element instance
for reservation in response.iterfind('reservationSet/item'):
    for instance in reservation.iterfind('instancesSet/item'):
        pprint(dictwalk(instance))
