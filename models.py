from app import db, ma

class User(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, unique=True, primary_key=True)
  spotify_id = db.Column(db.String(64), unique=True)
  oauth = db.Column(db.String(256), unique=True)
  refresh_tok = db.Column(db.String(256), unique=True)

  def __init__(self, user_id, oauth_token, refresh_token):
    self.spotify_id = user_id
    self.oauth = oauth_token
    self.refresh_tok = refresh_token

  def __repre__(self):
    return 'spotify id: {}>'.format(self.spotify_id)

class UserSchema(ma.Schema):
  class Meta:
    fields = ('spotify_id', 'id')
