from flask import Flask, request, jsonify, redirect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from urllib import parse
import spotipy
import spotipy.util as util
import spotipy.oauth2 as spotipy_auth
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
__spotify_auth__ = spotipy_auth.SpotifyOAuth(
        client_id = __client_id__,
        client_secret = __client_secret__,
        redirect_uri = __pub_host__,
        scope =  'user-read-currently-playing user-read-recently-played user-read-private'
    )
spotify_auth_endpoint = 'https://accounts.spotify.com/authorize/'

def _make_authorization_headers():
    auth_header = base64.b64encode(six.text_type(__client_id__ + ':' + __client_secret__).encode('ascii'))
    return {'Authorization': 'Basic %s' % auth_header.decode('ascii')}

class User(db.Model):
    id = db.Column(db.Integer, unique=True, primary_key=True)
    spotify_id = db.Column(db.String(64), unique=True)
    oauth = db.Column(db.String(256), unique=True)
    refresh_tok = db.Column(db.String(256), unique=True)

class UserSchema(ma.Schema):
    class Meta:
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
    spotify_auth = spotipy_auth.SpotifyOAuth(
        client_id = __client_id__,
        client_secret = __client_secret__,
        redirect_uri = __pub_host__,
        scope =  'user-read-currently-playing user-read-recently-played user-read-private'
    )
    return("Authorize here: " + spotify_auth.get_authorize_url())

@app.route("/", methods=["GET"])
def get_response_from_spotty():
    code = request.values['code']
    headers = _make_authorization_headers()
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

@app.route("/playmeamelody", methods=["GET", "POST"])
def get_tunes():
    songs = []
    for user in User.query.all():
        try:
            track = _get_currently_playing(user.oauth)
            if track:
                track = track['item']
                track_info = ''
                for i in track['artists']:
                    track_info += "%s, " %(i['name'])
                track_info = track_info[:-2]
                track_info += ": %s" %(track['name'])
                songs.append("%s -> %s" %(user.spotify_id, track_info))
        except SpotifyAuthTokenError:
            _renew_access_token(user)
            _get_currently_playing(user.oauth)
    if not songs:
        return jsonify({'text': "Its quiet...too quiet...get some music started g"})
    return jsonify({'text': '\n'.join(songs)})

def _get_currently_playing(access_token):
    headers = { 'Authorization': 'Bearer ' + access_token }
    response = requests.get('https://api.spotify.com/v1/me/player/currently-playing', headers=headers)
    if response.status_code == 200:
        r = json.loads(response.content)
        return(r)
    elif response.status_code == 401:
        raise SpotifyAuthTokenError("expired access token")


def _get_user_info(access_token):
    headers = { 'Authorization': 'Bearer ' + access_token }
    response = requests.get('https://api.spotify.com/v1/me', headers=headers)
    if response:
        r = json.loads(response.content)
        return(r)


def _add_new_minion(access_token, refresh_token):
    r = _get_user_info(access_token)
    if r:
        username = r['id']
        name = r['display_name']
        u = User.query.filter_by(spotify_id=username).first()
        if (u is None):
            u = User(spotify_id=username, oauth=access_token, refresh_tok=refresh_token)
        else:
            u.access_token = access_token
        db.session.add(u)
        db.session.commit()
        return(r)

def _renew_access_token(user):
    t = __spotify_auth__.refresh_access_token(refresh_token=user.refresh_tok)
    user_tok = t['access_token']
    ref_tok = t['refresh_token']
    user.oauth = user_tok
    user.refresh_tok = ref_tok
    db.session.add(user)
    db.session.commit()
    return (user)

if __name__ == "__main__":
    spotify_auth = spotipy_auth.SpotifyOAuth(
        client_id = __client_id__,
        client_secret = __client_secret__,
        redirect_uri = __pub_host__,
        scope =  'user-read-currently-playing user-read-recently-played user-read-private'
    )
    app.logger.setLevel(logging.DEBUG)
    app.run(debug=True, host="0.0.0.0", port="8888")


class SpotifyAuthTokenError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
