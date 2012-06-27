# dewpoint
urllib2 openers that sign requests for OAuth or Amazon APIs

## OAuth 2

```python
	import dewpoint.oauth as oauth
	import urllib2

	# Create an opener with only the consumer key and get a request token
	consumer = oauth.Consumer(OAUTH_CONSUMER_KEY, OAUTH_CONSUMER_SECRET)
	opener = urllib2.build_opener(oauth.OAuthHandler(consumer))

	req = oauth.Request('https://api.linkedin.com/uas/oauth/requestToken')
	resp = opener.open(req)
	request_token = urlparse.parse_qs(resp.read())
	request_token = oauth.Token(token['oauth_token'][0], token['oauth_token_secret'][0])

	# This is where you'd pass the user off to the API's authorize endpoint
	# which would bounce them back to your callback endpoint with an
	# oauth_verifier in the query string. We'll just assume that the variable
	# called "oauth_verifier" has been set to that.
	#oauth_verifier = request.params.get('oauth_verifier')

	# Now build another opener using the consumer and request tokens
	access_opener = urllib2.build_opener(oauth.OAuthHandler(consumer, request_token))
	req = oauth.Request('https://api.linkedin.com/uas/oauth/accessToken', oauth_params={'oauth_verifier': verifier})
	resp = access_opener.open(req)
	access_token = urlparse.parse_qs(resp.read())
	access_token = oauth.Token(access_token['oauth_token'], access_token['oauth_secret'])

	# Now we have an access token, we can do whatever we want, pretty
	# transparently
	import json
	user_opener = urllib2.build_opener(oauth.OAuthHandler(consumer, access_token))
	resp = user_opener.urlopen('https://api.linkedin.com/v1/people/~/connections:first-name,last-name,location,picture-url', headers={'x-li-format': 'json'})
	print json.loads(resp.read())
```

## Amazon Web Services

```python
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
```
