from flask import Flask, redirect, url_for, session, request, render_template
from flaskext.oauth import OAuth
import logging
import hmac
import hashlib
import base64
import json
import os
from urllib import urlencode
from config import *

app = Flask(__name__)
app.secret_key = 'abcdeghji'
app.debug = True
oauth = OAuth()

facebook = oauth.remote_app('facebook',
    base_url=BASE_URL,
    request_token_url=REQUEST_TOKEN_URL,
    access_token_url=ACCESS_TOKEN_URL,
    authorize_url=AUTHORIZE_URL,
    consumer_key=CONSUMER_KEY,
    consumer_secret=CONSUMER_SECRET,
    request_token_params={'scope': 'email'},
)

def validate_signed_fb_request(signed_request):
    """ Returns dictionary with signed request data """
    try:
        l = signed_request.split('.', 2)
        encoded_sig = str(l[0])
        payload = str(l[1])
    except IndexError:
        raise ValueError("'signed_request' malformed")
    
    sig = base64.urlsafe_b64decode(encoded_sig + "=" * ((4 - len(encoded_sig) % 4) % 4))
    data = base64.urlsafe_b64decode(payload + "=" * ((4 - len(payload) % 4) % 4))
    
    data = json.loads(data)
    
    if data.get('algorithm').upper() != 'HMAC-SHA256':
        raise ValueError("'signed_request' is using an unknown algorithm")
    else:
        expected_sig = hmac.new(CONSUMER_SECRET, msg=payload, digestmod=hashlib.sha256).digest()
    logging.debug("Signature: %s" % sig)
    logging.debug("Expected Signature: %s" % expected_sig)
    if sig != expected_sig:
        raise ValueError("'signed_request' signature mismatch")
    else:
        return data

@app.route('/', methods=['GET', 'POST'])
def index():
    signed_data = validate_signed_fb_request(request.form['signed_request'])
    if signed_data.has_key('oauth_token'):
        #print signed_data['oauth_token']
        session['oauth_token'] = (signed_data['oauth_token'], '')
        session['user'] = signed_data['user_id']
        logging.debug('Logged user: %s', signed_data)
        #return redirect(url_for('home'))
        #return redirect(url_for('facebook_authorized'))
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return facebook.authorize(callback=url_for('facebook_authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))

@app.route('/login/authorized')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        return 'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description']
        )
    session['oauth_token'] = (resp['access_token'], '')
    me = facebook.get('/me')
    return 'Logged in as id=%s name=%s redirect=%s' % \
        (me.data['id'], me.data['name'], request.args.get('next'))

@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('oauth_token')

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)-15s %(message)s')
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
    
    
    
    
    
    
    