################################################################################
# Weavrs OAuth API v1 Example
# Copyright (c) 2011 PhilterPhactory Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
################################################################################

"""
This is a simple App Engine-based example Prosthetic.
It shows how to connect to the Weavrs server using the OAuth API,
query a Weavr's state and push to its publishing stream.
"""

################################################################################
# Imports
################################################################################

import os
import re
import httplib
import logging
import oauth.oauth as oauth
import simplejson

from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp.util import run_wsgi_app
from google.appengine.ext.webapp import template

try:
    from google.appengine.api.taskqueue import Task
except:
    from google.appengine.api.labs.taskqueue import Task


################################################################################
# Configuration
# Set these to your App Engine Instance and your Prosthetic OAuth keys
# Create your Prosthetic at http://weavrs.com/developer/
################################################################################

# address of this server. Leave as None to guess. You will need to set
# this manually if you have your own domain name.
THIS_SERVER = None

CONSUMER_KEY = 'YOUR-PROSTHETIC-KEY'
CONSUMER_SECRET = 'YOUR-PROSTHETIC-SECRET'


################################################################################
# API URLs
# You don't need to edit these
################################################################################

API_SERVER = 'weavrs.com'

OAUTH_SERVER_PATH = 'http://%s/oauth' % API_SERVER
REQUEST_TOKEN_URL = OAUTH_SERVER_PATH + '/request_token/'
ACCESS_TOKEN_URL = OAUTH_SERVER_PATH + '/access_token/'
AUTHORIZATION_URL = OAUTH_SERVER_PATH + '/authorize/'

API_SERVER_PATH = 'http://%s/api/1' % API_SERVER
STATE_URL = API_SERVER_PATH + '/weavr/state/'
POST_URL = API_SERVER_PATH + '/weavr/post/'


# guess local server name if needed
if not THIS_SERVER:
    APPENGINE_DEV = os.environ.get("SERVER_SOFTWARE", "").startswith("Dev")
    INSTANCE_NAME = os.environ.get("APPLICATION_ID", "localhost")
    if APPENGINE_DEV:
        THIS_SERVER = "localhost:8080"
    else:
        THIS_SERVER = "%s.appspot.com"%INSTANCE_NAME

LOCAL_CALLBACK_URL = 'http://%s/oauth_callback/' % THIS_SERVER



################################################################################
# Data Models
################################################################################

class RequestToken(db.Model):
    """An OAuth Request Token"""
    oauth_key = db.StringProperty()
    oauth_secret = db.StringProperty()
    oauth_verifier = db.StringProperty()
    authorized = db.BooleanProperty()
    created = db.DateTimeProperty(auto_now_add=True)

class AccessToken(db.Model):
    """An OAuth Access Token"""
    oauth_key = db.StringProperty()
    oauth_secret = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)


class ProstheticData(db.Model):
    """The Prosthetic OAuth authorization required to access the Weavr,
       and the state data for the Weavr's instance of the Prosthetic"""
    request_token = db.ReferenceProperty(RequestToken)
    access_token = db.ReferenceProperty(AccessToken)
    previous_emotion = db.StringProperty(default="nothing")


def request_token_for_key(key):
    """Get the RequestToken object for the given key, or None if invalid"""
    return RequestToken.gql('WHERE oauth_key = :key', key=key).get()


def prostheticconnectdata_for_key(key):
    """Get the ProstheticData object for the given key, or None if invalid"""
    return ProstheticData.get(key)


def prostheticdata_for_access_token(token):
    """Get the ProstheticData object for the given token, or None if invalid"""
    return ProstheticData.gql('WHERE access_token = :token', token=token).get()


################################################################################
# API OAuth Access class
################################################################################

class OAuthWranglerException(Exception):
    def __init__(self, status, body):
        super(OAuthWranglerException, self).__init__(body)
        self.status = status
    
class OAuthWrangler(object):
    """OAuth registration and resource access support"""

    def __init__(self):
        """Create the objects we need to connect to an OAuth server"""
        self.connection = httplib.HTTPConnection(API_SERVER)
        self.connection.set_debuglevel(100)
        self.consumer = oauth.OAuthConsumer(CONSUMER_KEY, CONSUMER_SECRET)
        self.signature_method_plaintext = oauth.OAuthSignatureMethod_PLAINTEXT()
        self.signature_method_hmac_sha1 = oauth.OAuthSignatureMethod_HMAC_SHA1()

    def parse_response(self, response):
        status = response.status
        body = response.read()
        
        if '\n\n' in body and re.search(r'\nStatus: \d+', body):
            # some server problem is returning headers in the body.
            status_match = re.search(r'\nStatus: (\d+)', body)
            status = int(status_match.group(1))
            body = body.split('\n\n')[1]

        if status < 200 or status >= 300:
            logging.error("unexpected server response %d"%(status))
            raise OAuthWranglerException(status, body)

        return body


    def get_request_token(self):
        """Get the initial request token we can exchange for an access token"""
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(\
            self.consumer, callback=LOCAL_CALLBACK_URL,
            http_url=REQUEST_TOKEN_URL)
        oauth_request.sign_request(self.signature_method_plaintext,
                                   self.consumer, None)
        self.connection.request(oauth_request.http_method, REQUEST_TOKEN_URL,
                                headers=oauth_request.to_header())
        response = self.connection.getresponse()
        body = self.parse_response(response)
        return oauth.OAuthToken.from_string(body)


    def authorize_request_token_url(self, token):
        """Get the url to use to authorize the token"""
        oauth_request = oauth.OAuthRequest.from_token_and_callback(\
            token=token, http_url=AUTHORIZATION_URL, 
            callback=LOCAL_CALLBACK_URL)
        return oauth_request.to_url()

    def get_access_token(self, token, verifier):
        """Exchange the request token for an access token"""
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(\
            self.consumer, token=token, verifier=verifier, 
            http_url=ACCESS_TOKEN_URL)
        oauth_request.sign_request(self.signature_method_plaintext, 
                                   self.consumer, token)
        self.connection.request(oauth_request.http_method, ACCESS_TOKEN_URL,
                                headers=oauth_request.to_header())
        response = self.connection.getresponse()
        body = self.parse_response(response)
        return oauth.OAuthToken.from_string(body)

    def get_resource(self, token, resource_url, paramdict):
        """GET an OAuth resource"""
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(\
            self.consumer, token=token, http_method='GET',
            http_url=resource_url, parameters=paramdict)
        oauth_request.sign_request(self.signature_method_hmac_sha1, 
                                   self.consumer, token)
        self.connection.request(oauth_request.http_method,
                                oauth_request.to_url())
        response = self.connection.getresponse()
        return self.parse_response(response)

    def post_resource(self, token, resource_url, paramdict):
        """POST an OAuth resource"""
        oauth_request = oauth.OAuthRequest.from_consumer_and_token(\
            self.consumer, token=token, http_method='POST',
            http_url=resource_url, parameters=paramdict)
        oauth_request.sign_request(self.signature_method_hmac_sha1,
                                   self.consumer, token)
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        self.connection.request(oauth_request.http_method, resource_url,
                                body=oauth_request.to_postdata(),
                                headers=headers)

        response = self.connection.getresponse()
        return self.parse_response(response)


################################################################################
# URL Handlers
################################################################################

class RedirectToAuthorize(webapp.RequestHandler):
    """Redirects the user from our app to the Weavrs server to begin the OAuth
       authorization process"""

    def get(self):
        """Get the initial access token and send the user to authorize it"""
        wrangler = OAuthWrangler()
        token = wrangler.get_request_token()
        # Save the token ready for the callback
        request_token = RequestToken(oauth_key=token.key,
                                     oauth_secret=token.secret)
        request_token.save()
        start = wrangler.authorize_request_token_url(token)
        self.redirect(start)


class AcceptAuthorization(webapp.RequestHandler):
    """Our authorization callback that lets the Weavrs server return the
       user's authorization to us"""

    def return_error(self, reason):
        """Lots can go wrong in OAuth, so report it informatively to users"""
        path = os.path.join(os.path.dirname(__file__), 'templates', 'error.html')
        self.response.out.write(template.render(path, { "reason":reason }))

    def get(self):
        """Accept the authorization from the server and store the data we use
           to communicate with the Weavr"""
        logging.info(self.request.url)
        verifier = self.request.get('oauth_verifier')
        token = self.request.get('oauth_token')
        confirmed = self.request.get('oauth_callback_confirmed')
        # Make sure we have the required parameters
        if (not verifier) or (not token):
            self.return_error('Missing parameter(s)')
            return
        if not confirmed:
            self.return_error('Permission not confirmed.')
            return

        request_token = request_token_for_key(token)
        if not request_token:
            self.return_error("Couldn't find Token")
            return

        wrangler = OAuthWrangler()

        # Now get the access token
        verified_token = oauth.OAuthToken(request_token.oauth_key, request_token.oauth_secret)
        access_token = wrangler.get_access_token(verified_token, verifier)

        # fetch state from server to demonstrate that the access token works.
        try:
            state_string = wrangler.get_resource(access_token, STATE_URL, {})
            state = simplejson.loads(state_string)
        except Exception, e:
            self.return_error("Couldn't fetch weavr state: %s"%e)
            return

        # store the access token in the datastore
        obj = AccessToken(oauth_key=access_token.key, oauth_secret=access_token.secret)
        obj.put()

        prosthetic = ProstheticData(request_token=request_token, access_token=obj)
        prosthetic.put()
        
        # all done!
        path = os.path.join(os.path.dirname(__file__), 'templates', 'success.html')
        self.response.out.write(template.render(path, { "state":state }))



class HandleRunCron(webapp.RequestHandler):
    """Use App Engine's cron system to periodically queue run tasks for each
       Weavr. This simple method won't scale very far, but works for a demo."""

    def get(self):
        """Queue run tasks for each registered Weavr"""
        logging.info("Running cron job. Queueing run tasks.")
        for prosthetic in ProstheticData.all(keys_only=True):
            logging.info("Queueing run task for %s" % str(prosthetic))
            task = Task(url='/runner/prosthetic_task/', method='GET', 
                        params={'key': str(prosthetic)})
            task.add('default')
        logging.info("Finished running cron job.")


class HandleProstheticTask(webapp.RequestHandler):
    """Handle a run task for a Weavr"""

    def get_emotion(self, token):
        """Fetch the emotion of the Weavr's most recent run from the server
           using the API"""
        wrangler = OAuthWrangler()
        state_string = wrangler.get_resource(token, STATE_URL, {})
        state = simplejson.loads(state_string)
        return state['emotion']


    def post_message(self, token, message, emotion):
        """Post a message to the Weavr's publishing stream on the server using
           the API"""
        logging.info("posting status '%s' while feeling '%s'"%(message, emotion))
        wrangler = OAuthWrangler()
        wrangler.post_resource(token,
                                    POST_URL,
                                    {'category': 'status',
                                     'status': message,
                                     'keywords': emotion})


    def get(self):
        """Handle the run task request"""
        connection_key = self.request.get('key')
        data = prostheticconnectdata_for_key(connection_key)
        token = oauth.OAuthToken(key=data.access_token.oauth_key,
                                      secret=data.access_token.oauth_secret)

        try:
            emotion = self.get_emotion(token)
        except OAuthWranglerException, e:
            if e.status == 401:
                logging.warn("token has been revoked!")
                #FIXME: Handle de-authorized Weavrs and remove the data objects for them
                return
            else:
                raise
            

        if emotion != data.previous_emotion:
            message = "I was feeling %s, but now I'm %s"%(data.previous_emotion, emotion)
            # The emotion changed, so save it
            data.previous_emotion = emotion
            data.put()
        else:
            message = "I am still feeling %s"%emotion

        self.post_message(token, message, emotion)


class Homepage(webapp.RequestHandler):
    """The page users see when they arrive at our app's site."""

    def get(self):
        """Tell the user about the app and let them start authorizing access
           to a Weavr"""
        path = os.path.join(os.path.dirname(__file__), 'templates', 'homepage.html')
        self.response.out.write(template.render(path, {}))


################################################################################
# Main application configuration and flow of execution
# Hook up our URL handlers, and run
################################################################################

application = webapp.WSGIApplication([('/',
                                       Homepage),
                                      ('/start_authorizing/',
                                       RedirectToAuthorize),
                                      ('/oauth_callback/',
                                       AcceptAuthorization),
                                      ('/runner/run_cron/',
                                       HandleRunCron),
                                      ('/runner/prosthetic_task/',
                                       HandleProstheticTask),
                                      ],
                                     debug=True)


def main():
    """Accept connections and dispatch them"""
    run_wsgi_app(application)


if __name__ == "__main__":
    main()
