from flask import Flask, request, jsonify
from flask_heroku import Heroku
from flask_cors import CORS
from spotibot_client import Spotibot, SpotifyAuthTokenError
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
import os
import random
import json


app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
hku = Heroku(app)
ma = Marshmallow(app)
db = SQLAlchemy(app)

from models import User, UserSchema

__spibot__ = Spotibot(os.environ["SLACK_API_TOKEN"])

@app.route("/user", methods=["GET"])
def get_user():
    all_users = User.query.all()
    result = users_schema.dump(all_users)
    return jsonify(result.data)

@app.route("/nowplaying", methods=["GET"])
def get_nowplaying():
    return jsonify(get_tunes_detailed())

@app.route("/authdjrobot", methods=["POST"])
def authorizeDjRobot():
    slack_request = request.get_json()
    if "challenge" in slack_request:
        return(slack_request["challenge"])
    elif "event" in slack_request:
        event = slack_request["event"]
        return(handle_event(event))

@app.route("/", methods=["GET"])
def get_response_from_spotty():
    code = request.values['code']
    access, refresh =__spibot__.parse_spotify_response(code)
    return(__create_user__(access, refresh))

@app.route("/authorizeme", methods=["GET", "POST"])
def get_authorization_token():
  if request.method == 'GET':
      return(jsonify("Authorize here: %s ", __spibot__.get_authorize_url()))
  else:
      return(jsonify("Error"))

def __create_user__(access_token, refresh_token):
    app.logger.error("access: %s refresh: %s", access_token, refresh_token)
    if access_token and refresh_token:
        r = __spibot__.get_user_info(access_token)
        if r:
            username = r['id']
            name = r['display_name']
            u = User.query.filter_by(spotify_id=username).first()
            if (u is None):
                u = User(username, access_token, refresh_token)
            else:
                u.access_token = access_token
            db.session.add(u)
            db.session.commit()
            return(jsonify("success!"))
    return(jsonify("error adding new user"))

def handle_event(event):
    event_text = event["text"]
    peer_dj = event["user"]
    channel = event["channel"]
    if "new dj" in event_text:
        return __spibot__.send_authorization_pm(peer_dj, channel)
    elif "shuffle" in event_text:
        return __spibot__.send_currently_playing_list(channel, get_tunes())
    else:
        return requests.make_response("invalid event", 500)

def get_random_fake_song():
    fileKey = random.randint(0,3)
    with open('sampleResponses/{}.json'.format(fileKey), 'r') as file:
        return json.loads(file.read())


def get_tunes():
    songs = []
    for user in User.query.all():
        try:
            track = __spibot__.get_currently_playing(user.oauth)
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
            __spibot__.get_currently_playing(user.oauth)
    if not songs:
        return "Its quiet...too quiet...get some music started g"
    return '\n'.join(songs)

def get_tunes_detailed():
    songs = []
    for user in User.query.all():
        try:
            track = __spibot__.get_currently_playing(user.oauth)
            if track:
                songs.append({"user":user.spotify_id,"track":track})
        except SpotifyAuthTokenError:
            _renew_access_token(user)
            __spibot__.get_currently_playing(user.oauth)
    if not songs:
        return { "error": "Its quiet...too quiet...get some music started g"}
    return songs

def _renew_access_token(user):
    t = __spibot__.get_new_access_token(refresh_token=user.refresh_tok)
    user_tok = t['access_token']
    ref_tok = t['refresh_token']
    user.oauth = user_tok
    user.refresh_tok = ref_tok
    db.session.add(user)
    db.session.commit()
    return (user)

user_schema = UserSchema()
users_schema = UserSchema(many=True)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="8888")
    app.config['DEBUG'] = True
