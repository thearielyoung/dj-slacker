from flask import make_response
from slackclient import SlackClient
import base64, requests, six, json, os
import spotipy.oauth2 as spotipy_auth

__client_id__ =  os.environ["CLIENT_ID"]
__client_secret__ = os.environ["CLIENT_SECRET"]
__pub_host__ = "https://dj-slacker.herokuapp.com/"
__spotify_auth__ = spotipy_auth.SpotifyOAuth(
        client_id =__client_id__,
        client_secret = __client_secret__,
        redirect_uri = 'https://dj-slacker.herokuapp.com/',
        scope =  'user-read-currently-playing user-read-recently-played user-read-private'
    )

class Spotibot:

    def _make_authorization_headers(self):
        auth_header = base64.b64encode(six.text_type(__client_id__ + ':' + __client_secret__).encode('ascii'))
        return {'Authorization': 'Basic %s' % auth_header.decode('ascii')}

    def get_new_access_token(self, refresh_token):
        return __spotify_auth__.refresh_access_token(refresh_token=refresh_token)

    def get_currently_playing(self, access_token):
        headers = { 'Authorization': 'Bearer ' + access_token }
        response = requests.get('https://api.spotify.com/v1/me/player/currently-playing', headers=headers)
        if response.status_code == 200:
            r = json.loads(response.content)
            return(r)
        elif response.status_code == 401:
            raise SpotifyAuthTokenError("expired access token")

    def get_user_info(self, access_token):
        headers = { 'Authorization': 'Bearer ' + access_token }
        response = requests.get('https://api.spotify.com/v1/me', headers=headers)
        if response:
            r = json.loads(response.content)
            return(r)

    def parse_spotify_response(self, spotify_code):
        headers = self._make_authorization_headers()
        resp = json.loads(requests.post('https://accounts.spotify.com/api/token',
            data = {
              "redirect_uri": __pub_host__,
              "grant_type": "authorization_code",
              "code": spotify_code },
            headers=headers).content)
        access_token = resp['access_token']
        refresh_tok = resp['refresh_token']
        return (access_token, refresh_tok)

    def send_authorization_pm(self, peer_dj, channel):
        self.__sc__.api_call(
        "chat.postMessage",
        channel=peer_dj,
        text="Authorize here: %s" % __spotify_auth__.get_authorize_url()
        )
        return make_response("DJ Added", 200)

    def send_currently_playing_list(self, channel, playlist):
        self.__sc__.api_call(
        "chat.postMessage",
        channel=channel,
        text=playlist
        )
        return make_response("Songs fetched", 200)

    def __init__(self, slack_api_token):
        self.__sc__ = SlackClient(slack_api_token)

class SpotifyAuthTokenError(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)
