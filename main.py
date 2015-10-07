#!/usr/bin/env python


from base import BaseHandler
from google.appengine.ext import ndb

import logging
import webapp2


from models import Group
from models import GroupMembership
from models import Message

from usermanagement import user_required
from usermanagement import SignupHandler
from usermanagement import VerificationHandler
from usermanagement import SetPasswordHandler
from usermanagement import LoginHandler
from usermanagement import LogoutHandler
from usermanagement import ForgotPasswordHandler


class MainHandler(BaseHandler):
    def get(self):
        self.render_template('home.html')

class MyselfHandler(BaseHandler):
    @user_required
    def get(self):
        self.render_template('myself.html')

class CreateGroupHandler(BaseHandler):
    @user_required
    def get(self):
        self.render_template('creategroup.html')

    @user_required
    def post(self):
        name = self.request.get('name')
        description = self.request.get('description')

        newGroup = Group(name = name, description = description)
        newGroup.put()

        newGroupMembership = GroupMembership()
        newGroupMembership.groupKey = newGroup.key
        newGroupMembership.userKey = self.user.key
        newGroupMembership.isAdministrator = True
        newGroupMembership.isModerator = True
        newGroupMembership.put()

        self.redirect(self.uri_for('home'))



def group_required(handler):

    def check_group(self, *args, **kwargs):

        logging.info('check_group')

        if not 'groupname' in kwargs:
            logging.error('No groupname although expected')
            self.display_message('No groupname provided.')

        groupName = kwargs['groupname']
        print(groupName)
        query = Group.query(Group.name == groupName)
        groups = query.fetch()
        if len(groups) == 1:
            thisGroup = groups[0]
        else:
            thisGroup = None

        if not thisGroup:
            logging.error('Group "{groupname}" not found'.format(groupname = groupName))
            self.redirect(self.uri_for('home'), abort=True)

        self.group = thisGroup

        if handler:
            return handler(self, *args, **kwargs)

        return handler

    return check_group

def group_membership_required(handler):

    def check_membership(self, *args, **kwargs):

        logging.info('check_group_membership')

        thisUser = self.user
        thisGroup = self.group

        query = GroupMembership.query(GroupMembership.userKey==thisUser.key,
                                      GroupMembership.groupKey==thisGroup.key)
        memberships = query.fetch()

        if len(memberships) == 0:
            logging.info('"{user}" is not a member of group "{groupname}"'.format(user=thisUser.name, groupname=thisGroup.name))
            self.display_message('You are not a member of this group')
            return
        elif len(memberships) > 1:
            logging.info('"{user}" returns multiple memberships of group "{groupname}"'.format(user=thisUser.name, groupname=thisGroup.name))
            self.display_message('Something went wrong with your membership')
            return

        print(memberships)
        print(len(memberships))
        self.group_membership = memberships[0]

        if handler:
            return handler(self, *args, **kwargs)

        return handler#

    return check_membership

class ListGroupsHandler(BaseHandler):

    @user_required
    def get(self):
        groupsQuery = Group.query()
        groups = groupsQuery.fetch()

        membershipQuery = GroupMembership.query(GroupMembership.userKey==self.user.key)
        memberships = membershipQuery.fetch()


        membershipStatus = []

        for group in groups:

            foundMembership = False
            for membership in memberships:
                if membership.groupKey == group.key:
                    foundMembership = True
                    break

            membershipStatus.append(foundMembership)


        params = {'groupsAndMemberships': zip(groups, membershipStatus)}

        self.render_template('listgroups.html', params=params)

class JoinGroupHandler(BaseHandler):

    @user_required
    @group_required
    def get(self, *args, **kwargs):

        # Check if user already has a membership relation with this group
        query = GroupMembership.query(GroupMembership.userKey == self.user.key,
                                      GroupMembership.groupKey == self.group.key)
        membership = query.fetch()

        # If there is no membership for this user, create one
        if len(membership) == 0:
            newGroupMembership = GroupMembership()
            newGroupMembership.userKey = self.user.key
            newGroupMembership.groupKey = self.group.key
            newGroupMembership.isAdministrator = False
            newGroupMembership.isModerator = False
            newGroupMembership.isPending = True
            newGroupMembership.put()
            self.display_message('Mitgliedschaft wurde beantragt')
        else:
            self.display_message('Du hast bereits eine Mitgliedschaft beantragt')


class AcceptMemberHandler(BaseHandler):

    @user_required
    @group_required
    @group_membership_required
    def get(self, *args, **kwargs):

        requestingUser = self.user_model.get_by_id(int(kwargs['user_id']))

        requestingUsersMembershipQuery = GroupMembership.query(GroupMembership.groupKey == self.group.key,
                                                               GroupMembership.userKey == requestingUser.key)

        requestingUsersMembership = requestingUsersMembershipQuery.fetch()

        if len(requestingUsersMembership) == 1:
            if kwargs['action'] == 'refuse':
                requestingUsersMembership[0].key.delete()
            elif kwargs['action'] == 'accept':
                requestingUsersMembership[0].isPending = False
                requestingUsersMembership[0].put()

        self.redirect('/{groupname}/show/'.format(groupname = self.group.name))


class ShowGroupHandler(BaseHandler):

    @user_required
    @group_required
    @group_membership_required
    def get(self, *args, **kwargs):

        params = dict()
        params['group'] = self.group

        if self.group_membership.isPending == True:
            self.display_message('Dein Aufnahmeantrag fuer diese Gruppe wurde noch nicht bearbeitet')
            return

        messagesQuery = Message.query(ancestor=self.group.key).order(Message.created)
        messages = messagesQuery.fetch()
        userKeys = []

        for message in messages:
            userKeys.append(message.userKey)

        users = ndb.get_multi(userKeys)
        params['messages'] = zip(messages, users)

        if self.group_membership.isModerator:
            requestsQuery = GroupMembership.query(GroupMembership.groupKey == self.group.key,
                                                  GroupMembership.isPending == True)

            requests = requestsQuery.fetch()
            requestingUserKeys = []
            for request in requests:
                requestingUserKeys.append(request.userKey)

            requestingUsers = ndb.get_multi(requestingUserKeys)
            print(requestingUsers)
            params['member_requests'] = requestingUsers


        self.render_template('showgroup.html', params=params)

    def post(self, *args, **kwargs):
        groupname = kwargs['groupname']
        query = Group.query(Group.name == groupname)
        groups = query.fetch()
        if len(groups) == 1:
            thisGroup = groups[0]
        else:
            thisGroup = None


        user = self.user

        print(user)
        if user:
            memberships = GroupMembership.query(GroupMembership.userKey == user.key,
                                                GroupMembership.groupKey == thisGroup.key).fetch()
            if len(memberships) == 1:
                membership = memberships[0]
                print(membership)
            else:
                self.display_message('You can only post if you\'re a member')

                return

        if user:
            print(self.request.get('message'))
            newMessage = Message(parent=thisGroup.key, userKey=user.key, text=self.request.get('message'))
            newMessage.put()

        self.redirect('/{groupname}/show'.format(groupname = groupname))


config = {
    'webapp2_extras.auth': {
        'user_model': 'models.User',
        'user_attributes': ['name']
    },
    'webapp2_extras.sessions': {
        'secret_key': 'YOUR_SECRET_KEY'
    }
}

app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
                  handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/authenticated', MyselfHandler, name='authenticated'),
    webapp2.Route('/creategroup', CreateGroupHandler, name='creategroup'),
    webapp2.Route('/listgroups', ListGroupsHandler, name='listgroups'),
    webapp2.Route('/<groupname:.+>/show', ShowGroupHandler),
    webapp2.Route('/<groupname:.+>/join', JoinGroupHandler),
    webapp2.Route('/<groupname:.+>/<action:refuse|accept>/<user_id:\d+>', AcceptMemberHandler)

], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)
