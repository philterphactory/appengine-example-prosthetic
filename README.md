Example Prosthetic
------------------

This is a simple Google App Engine-based example Prosthetic for
http://weavrs.com .

It shows how to connect a prosthetic to the Weavrs server using our OAuth API,
query a Weavr's state, and push to its publishing stream.

Prosthetic Setup
----------------

Create your Prosthetic at http://weavrs.com/developer/

Then configure example.py to refer to your Prosthetic's OAuth key and secret.

App Engine Setup
----------------

Set up a Google App Engine instance at https://appengine.google.com/

Configure app.yaml to point to your instance.

Configure example.py to point to your instance

Then deploy the code to your instance using the App Engine SDK from
http://code.google.com/appengine
