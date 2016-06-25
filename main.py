#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2

import os
import jinja2
import re
import hashlib
import hmac
import random
import string
from string import letters

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__),'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

secure_str = 'abcde'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
def valid_email(email):
    return EMAIL_RE.match(email)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

def make_hash(s):
    return hmac.new(secure_str,s).hexdigest()

def make_secure_cookie(val):
    return '%s|%s' % (val, make_hash(val))

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_cookie(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(name, pw, salt=None):
    # generate the hashed password for storage safety
    if not salt:
        salt = make_salt()
    res = hashlib.sha256(name+pw+salt).hexdigest()
    return res+","+salt

def validate_pw(name,pw,pw_hash):
    salt = pw_hash.split(",")[1]
    return pw_hash == make_pw_hash(name,pw,salt)


class User(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name,pw)
        u= User(username = name, pw_hash = pw_hash, email = email)
        return u

    @classmethod
    def find_by_name(cls, name):
        u = User.all().filter("username =", name).get()
        #u = db.GqlQuery("SELECT * FROM User where username = :num",num=name)
        return u

    @classmethod
    def find_by_id(cls, uid):
        return User.get_by_id(uid)   

    @classmethod
    def validate_login(cls, name, pw):
        u = User.all().filter("username =", name).get()
        #u = User.find_by_name(name)
        if u and validate_pw(name, pw, u.pw_hash):
            return u

class Blog(db.Model):   
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    writer = db.ReferenceProperty(User, collection_name='blogs')

    @classmethod
    def by_title(cls, uname):
        u = Blog.all().filter('title =', uname).get()
        return u

class Comment(db.Model):  
    Commenter = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    post =  db.ReferenceProperty(Blog, collection_name='comments')

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        params['user'] = self.user
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))
    
    def set_cookie(self, username):
        value = str(username)
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % value)
   
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def read_secure_id(self):
        cookie_val = self.request.cookies.get('user_id',None)
        if cookie_val:
            return check_secure_val(cookie_val)
    
    # this function is called for initialization when the Handler object is created
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_id()
        if uid:
            self.user = User.find_by_id(int(uid))
        else:
            self.user = None

    def login(self, u):
        value = str(u.key().id())
        cookie_value = make_secure_cookie(value)
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % cookie_value)

class SignHandler(Handler):
    # new user registration page
    def get(self):
        self.render('signup.html')
    
    def post(self):
        if self.user:
            self.render('signup.html', error = "you must logout and then register", user = self.user)
            return
        
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        params=dict(ua = username,
                      ema = email)
        
        if valid_username(username) == None:
             params['username_error'] = 'username is invalid'

        if password != verify:
             params['password_equality_error'] = "password not equal"

        if valid_password(password) == None:
            params['password_error'] = 'password is invalid'

        if len(email) > 0 and valid_email(email) == None:
            params['email_error'] = 'email is invalid'

        if len(params) > 2:
            self.render('signup.html', **params)    
        else:
            u = User.find_by_name(username)
            if u:
                self.render('signup.html', username_error='This user has already existed')
            else:
                new_user = User.register(username,password,email)
                new_user.put()
                self.login(new_user)
                self.redirect('/welcome')

class Login(Handler):
    # the login page
    def get(self):
        self.render('login.html')

    def post(self):
        if self.user:
            self.render("login.html", error = 'you must logout and then login')
            return
        username = self.request.get("username")
        password = self.request.get("password")
        u = User.validate_login(username, password)
        if not u:
            self.render("login.html", error = 'invalid login')
        else:
            self.login(u)
            self.redirect('/welcome')

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect("/signup")
        
class WelHandler(Handler):
    # welcome the user who login or signup
    def get(self):
        if self.user:
            users = User.all()
            self.render("welcome.html", username = self.user.username, users = users)
        else:
            self.redirect("/signup")

class BlogHandler(Handler):
    # list all the blogs in the page
    def get(self):
        blogs=Blog.all()
        self.render("blogs.html", blogs = blogs)

class NewPostHandler(Handler):
    # create a new blog
    def get(self):
    	if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")
    
    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")
        if title and content:
            a= Blog(title = title, content = content, writer = self.user)
            a.put()
            self.redirect('/blog/%s' % str(a.key().id()))
        else:
            error = "we need both a title and some artwork"
            self.render("newpost.html",title = title, content = content, error = error)

class PostPage(Handler):
    # blog post page
    def get(self, post_id):
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post = post)

    def post(self, post_id):       
        content= self.request.get("comment")
        key = db.Key.from_path('Blog', int(post_id))
        post = db.get(key)
        if not content:
            error = "the comment cannot be empty"
            self.render("permalink.html", error = error,post = post)
        else:
            new_comment = Comment(Commenter = self.user.username, content = content, post = post )
            new_comment.put()
            self.redirect('/blog/%s' % str(post.key().id()))

class EditBlogHandler(Handler):
    # editing blog page
    def get(self):
        if not self.user:
        	self.redirect("/login")
        	return
        post_id = self.request.get('id')
        key = db.Key.from_path('Blog', int(post_id))
        blog = db.get(key)
        if blog.writer.key().id() != self.user.key().id():
            self.render("editblog.html", user_error = "you can not edit the other user's blog", blog = blog, user = self.user)
        else:
            self.render("editblog.html", blog = blog)

    def post(self):
        post_id = self.request.get('id')
        key = db.Key.from_path('Blog', int(post_id))
        blog = db.get(key)
        title = self.request.get("title")
        content = self.request.get("content")
        if title and content:
            blog.title = title
            blog.content = content
            blog.put()
            self.redirect('/blog/%s' % str(blog.key().id()))
        else:
            error = "we need both a title and some artwork"
            self.render("editblog.html",title=title, content = content, error = error, blog = blog)

class DelBlogHandler(Handler):
    # deleting blog page
    def get(self):
        if not self.user:
            self.redirect("/login")
            return
        post_id = self.request.get('id')
        key = db.Key.from_path('Blog', int(post_id))
        blog = db.get(key)
        if blog.writer.key().id() != self.user.key().id():
            self.render('deleteblog.html', error = "you can not delete the other user's blog")
        else:
            self.render('deleteblog.html')

    def post(self):
        decision = self.request.get('N')
        if decision:
            self.redirect('/blog')
            return
        post_id = self.request.get('id')
        key = db.Key.from_path('Blog', int(post_id))
        blog = db.get(key)
        db.delete(key)
        self.redirect("/blog")

class ReadBlogHandler(Handler):
    # redirect to the blog page
    def get(self):
        post_id = self.request.get('id')
        self.redirect('/blog/%s' % str(post_id))

class MainHandler(webapp2.RequestHandler):
    def get(self):
        self.response.out.write("Hello World")

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ('/signup', SignHandler),
    ('/welcome', WelHandler),
    ('/login', Login),
    ('/logout', Logout),
    ('/blog', BlogHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/([0-9]+)', PostPage),
    ('/blog/edit', EditBlogHandler),
    ('/blog/delete', DelBlogHandler),
    ('/blog/details', ReadBlogHandler)
    ], debug=True)
