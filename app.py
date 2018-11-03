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
  id = db.Column(db.Integer, primary_key=True)
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

#@app.route("/playmeamelody", methods=["GET"])
#def get_currently_playing():
#  playlist = {}
#  all_users = User.query.all()
#  for user in all_users:
#    user.oauth

@app.route("/authorizeme", methods=["GET", "POST"])
def get_authorization_token():
  # if request.method == 'GET':
    payload = {
      'client_id': __client_id__,
      'response_type': 'code',
      'scope': 'user-read-currently-playing user-read-recently-played',
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
  app.logger.info(resp.keys())
  user_tok = resp['access_token']
  refresh_tok = resp['refresh_token']
  return(_add_new_minion(user_tok, refresh_tok)    )

@app.route("/playmeamelody", methods=["GET"])
def get_tunes():
  for user in User.query.all():
      try:
          return(jsonify(_get_currently_playing(user.oauth)))
      except SpotifyAuthTokenError:
          _renew_access_token(user)
          _get_currently_playing(user.access_token)

def _get_currently_playing(access_token):
  headers = { 'Authorization': 'Bearer ' + access_token }
  response = requests.get('https://api.spotify.com/v1/me/player/currently-playing', headers=headers)
  if response:
      r = json.loads(response.content)
      return(r)
  elif response.status_code == 401:
      raise SpotifyAuthTokenError("expired access token")

def _add_new_minion(access_token, refresh_token):
  r = _get_currently_playing(access_token)
  username = r['context']['uri']
  u = User.query.filter_by(spotify_id=username).first()
  if (u is None):
    new_minion = User(spotify_id = username.split(":")[2], oauth = access_token)
    db.session.add(new_minion)
  else:
    u.access_token = access_token
  db.session.commit()
  app.logger.info(u.spotify_id + " updated successfully")

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
  u.access_token = user_tok
  u.refresh_tok = refresh_token;
  db.session.commit()

if __name__ == "__main__":
  app.run(debug=True, host="0.0.0.0", port="8888")

class SpotifyAuthTokenError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
