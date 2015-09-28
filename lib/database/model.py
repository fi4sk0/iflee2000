import time
import webapp2_extras.appengine.auth.models

from google.appengine.ext import ndb

from webapp2_extras import security


class Group(ndb.Model):
    name = ndb.StringProperty()
    description = ndb.TextProperty()
    url = ndb.StringProperty()

class GroupOwnership(ndb.Model):
    groupKey = ndb.KeyProperty()
    userKey = ndb.KeyProperty()


class Event(ndb.Model):
    name = ndb.StringProperty()
    description = ndb.TextProperty()
    location = ndb.StringProperty()
    geoLocation = ndb.GeoPtProperty()
    startDate = ndb.DateTimeProperty()
    endDate = ndb.DateTimeProperty()

class Message(ndb.Model):
    user = ndb.UserProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)
    text = ndb.TextProperty()