from flask import Flask, request, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from urllib import parse
import os, base64, requests, six, json
import six.moves.urllib.parse as urllibparse

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'whatsgood.sqlite')
db = SQLAlchemy(app)
ma = Marshmallow(app)
__prefix__ = 'https://api.spotify.com/v1/'
__client_id__ = os.environ["CLIENT_ID"]
__client_secret__ = os.environ["CLIENT_SECRET"]
__pub_host__='https://dj-slacker.herokuapp.com/'

spotify_auth_endpoint = 'https://accounts.spotify.com/authorize/'

def _make_authorization_headers(client_id, client_secret):
    auth_header = base64.b64encode(six.text_type(client_id + ':' + client_secret).encode('ascii'))
    return {'Authorization': 'Basic %s' % auth_header.decode('ascii')}

class User(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    spotify_id = db.Column(db.String(64), unique=True)
    oauth = db.Column(db.String(256), unique=True)
    refresh_tok = db.Column(db.String(256), unique=True)

class UserSchema(ma.Schema):
    class Meta:
    # Fields to expose
        fields = ('spotify_id', 'id')

user_schema = UserSchema()
users_schema = UserSchema(many=True)

@app.route("/user", methods=["GET"])
def get_user():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result.data)

@app.route("/authorizeme", methods=["GET", "POST"])
def get_authorization_token():
    # if request.method == 'GET':
    payload = {
      'client_id': __client_id__,
      'response_type': 'code',
      'scope': 'user-read-currently-playing user-read-recently-played user-read-private',
      'redirect_uri': __pub_host__,
    }
    header_auth = _make_authorization_headers(__client_id__, __client_secret__)
    r = requests.get(url = spotify_auth_endpoint, params = payload, headers = header_auth)
    return("Authorize here: " + r.url)

@app.route("/", methods=["GET"])
def get_response_from_spotty():
    code = request.values['code']
    headers = _make_authorization_headers(__client_id__, __client_secret__)
    resp = json.loads(requests.post('https://accounts.spotify.com/api/token',
        data = {
          "redirect_uri": __pub_host__,
          "grant_type": "authorization_code",
          "code": code },
        headers=headers).content)
    access_token = resp['access_token']
    refresh_tok = resp['refresh_token']
    if _add_new_minion(access_token, refresh_tok):
        return(jsonify("success!"))

@app.route("/playmeamelody", methods=["GET"])
def get_tunes():
    songs = []
    for user in User.query.all():
        try:
            track = _get_currently_playing(user.oauth)['item']
            track_info = ''
            for i in track['artists']:
                app.logger.error(i)
                track_info += "%s " %(i['name'])
                track_info += ": %s" %(track['name'])
                songs.append(track_info)
            app.logger.error(songs)
        except SpotifyAuthTokenError:
            _renew_access_token(user)
            _get_currently_playing(user.access_token)
    return jsonify(songs)

def _get_currently_playing(access_token):
    headers = { 'Authorization': 'Bearer ' + access_token }
    response = requests.get('https://api.spotify.com/v1/me/player/currently-playing', headers=headers)
    if response:
        r = json.loads(response.content)

        return(r)
    elif response.status_code == 401:
        raise SpotifyAuthTokenError("expired access token")


def _get_user_info(access_token):
    headers = { 'Authorization': 'Bearer ' + access_token }
    response = requests.get('https://api.spotify.com/v1/me', headers=headers)
    app.logger.error(response.status_code)
    if response:
        r = json.loads(response.content)
        return(r)


def _add_new_minion(access_token, refresh_token):
    r = _get_user_info(access_token)
    username = r['id']
    u = User.query.filter_by(spotify_id=username).first()
    if (u is None):
        app.logger.error(username + " at: " + access_token)
        u = User(spotify_id=username, oauth=access_token, refresh_tok=refresh_token)
    else:
        u.access_token = access_token
    db.session.add(u)
    db.session.commit()
    app.logger.error(u.spotify_id + " updated successfully")
    return(r)

def _renew_access_token(user):
    headers = _make_authorization_headers(__client_id__, __client_secret__)
    resp = json.loads(requests.post('https://accounts.spotify.com/api/token',
        data = {
          "redirect_uri": __pub_host__,
          "grant_type": "authorization_code",
          "code": user.refresh_tok },
        headers=headers).content)
    user_tok = resp['access_token']
    refresh_token = resp['refresh_token']
    user.access_token = user_tok
    user.refresh_tok = refresh_token;
    db.session.add(user)
    db.session.commit()
    return (user)

if __name__ == "__main__":
  app.run(debug=True, host="0.0.0.0", port="8888")

class SpotifyAuthTokenError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
