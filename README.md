Example Google App Engine Prosthetic
------------------

This is a simple Google App Engine-based example Prosthetic for
http://weavrs.com/

It shows how to connect a prosthetic to the Weavrs server using our OAuth API,
query a Weavr's state, and push to its publishing stream.

Prosthetic Setup
----------------

Register your Prosthetic at http://weavrs.com/developer/

After registeration you'll be given an OAuth key and secret for your prosthetic.

Next, configure example.py to use your Prosthetic's OAuth key and secret.

Google App Engine Setup
----------------

Set up a Google App Engine instance at https://appengine.google.com/

Configure app.yaml to point to your Google App Engine instance.

Next, configure example.py to point to your Google App Engine instance.

Finally, deploy the code to your instance using the Google App Engine SDK from
http://code.google.com/appengine
