import time
import webapp2_extras.appengine.auth.models

from google.appengine.ext import ndb

from webapp2_extras import security

class User(webapp2_extras.appengine.auth.models.User):

    def set_password(self, raw_password):
        """Sets the password for the current user

        :param raw_password:
            The raw password which will be hashed and stored
        """
        self.password = security.generate_password_hash(raw_password, length=12)

    @classmethod
    def get_by_auth_token(cls, user_id, token, subject='auth'):
        """Returns a user object based on a user ID and token.

        :param user_id:
            The user_id of the requesting user.
        :param token:
            The token string to be verified.
        :returns:
            A tuple ``(User, timestamp)``, with a user object and
            the token timestamp, or ``(None, None)`` if both were not found.
        """
        token_key = cls.token_model.get_key(user_id, subject, token)
        user_key = ndb.Key(cls, user_id)
        # Use get_multi() to save a RPC call.
        valid_token, user = ndb.get_multi([token_key, user_key])
        if valid_token and user:
            timestamp = int(time.mktime(valid_token.created.timetuple()))
            return user, timestamp

        return None, None

class Group(ndb.Model):
    name = ndb.StringProperty()
    description = ndb.TextProperty()

class GroupMembership(ndb.Model):
    groupKey = ndb.KeyProperty()
    userKey = ndb.KeyProperty()
    isAdministrator = ndb.BooleanProperty()
    isModerator = ndb.BooleanProperty()

class Event(ndb.Model):
    name = ndb.StringProperty()
    description = ndb.TextProperty()
    location = ndb.StringProperty()
    geoLocation = ndb.GeoPtProperty()
    startDate = ndb.DateTimeProperty()
    endDate = ndb.DateTimeProperty()

class Message(ndb.Model):
    userKey = ndb.KeyProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    text = ndb.TextProperty()

class EventInterest(ndb.Model):
    eventKey = ndb.KeyProperty()
    userKey = ndb.KeyProperty()
