__author__ = 'tmaul'

from google.appengine.ext import ndb


class User(ndb.Model):
    name = ndb.StringProperty()
    email = ndb.StringProperty()
    phone = ndb.StringProperty()
    password = ndb.StringProperty()

class Group(ndb.Model):
    name = ndb.StringProperty()
    description = ndb.TextProperty()
    url = ndb.StringProperty()

class Event(ndb.Model):
    name = ndb.StringProperty()
    description = ndb.TextProperty()
    location = ndb.StringProperty()
    startDate = ndb.DateTimeProperty()
    endDate = ndb.DateTimeProperty()

