from pprint import pprint
import os

import dewpoint.aws


ec2 = dewpoint.aws.AWSProxy(
    key=os.environ['AWS_ACCESS_KEY_ID'],
    secret=os.environ['AWS_SECRET_ACCESS_KEY'],
    version='2012-06-01',
    endpoint='https://ec2.us-east-1.amazonaws.com')


response = ec2.DescribeInstances()
# response is an xml.etree.ElementTree.Element instance
for reservation in response.iterfind('reservationSet/item'):
    for instance in reservation.iterfind('instancesSet/item'):
    pprint(dewpoint.aws.dictwalk(instance))
