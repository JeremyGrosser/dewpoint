from dewpoint.oauth import Consumer, Token, OAuthHandler, Request

from pprint import pprint
import urllib2
import json
import sys

def three_legged_auth(consumer):
    opener = urllib2.build_opener(OAuthHandler(consumer))
    resp = opener.open(Request('https://api.twitter.com/oauth/request_token'))
    rtoken = urlparse.parse_qs(resp.read())
    rtoken = Token(rtoken['oauth_token'][0], rtoken['oauth_token_secret'][0])
    print 'Clicky clicky:', 'https://api.twitter.com/oauth/authorize?oauth_token=%s' % rtoken.key

    sys.stdout.write('OAuth verifier: ')
    verifier = sys.stdin.readline().rstrip('\r\n')

    opener = urllib2.build_opener(OAuthHandler(consumer, rtoken))
    resp = opener.open(Request('https://api.twitter.com/oauth/access_token', oauth_params={
        'oauth_verifier': verifier,
    }))
    atoken = urlparse.parse_qs(resp.read())
    atoken = Token(atoken['oauth_token'][0], atoken['oauth_token_secret'][0])
    opener = urllib2.build_opener(OAuthHandler(consumer, atoken))
    urllib2.install_opener(opener)

if __name__ == '__main__':
    three_legged_auth(Consumer(YOURAPIKEY, YOURAPISECRET))

    req = urllib2.urlopen('https://api.twitter.com/statuses/friends.json')
    pprint(json.loads(req.read()))
