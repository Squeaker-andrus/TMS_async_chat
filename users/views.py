import datetime
import re
import os
import hashlib
import aiohttp_jinja2
from aiohttp import web
from aiohttp.web_request import Request
from aiohttp_session import Session

from extra import redirect, login_required
from .models import User


class LogIn(web.View):

    @aiohttp_jinja2.template("users/login.html")
    async def get(self):
        return {}

    async def post(self):
        data = await self.request.post()
        username = data.get('username', '').lower()
        input_password = data.get('password', '')
        try:
            user = await User.get(username=username)

        except Exception as error:
            print(error)
            redirect(self.request, "login")
            return

        else:
            if input_password != hashlib.pbkdf2_hmac('sha256', input_password.encode('utf-8'), salt=User.get.password.key, 100000):
                redirect(self.request, "login")
            else:
                self.login(user)
        return web.json_response({"user": user.id})

    def login(self, user: User):

        self.request.session["user_id"] = user.id
        self.request.session["time"] = str(datetime.datetime.now())

        redirect(self.request, "home")


class Register(web.View):

    @aiohttp_jinja2.template("users/register.html")
    async def get(self):
        print(self.request)

    async def check_username(self) -> str:
        """ Get username from post data, and check is correct """
        data = await self.request.post()
        username = data.get('username', '').lower()
        if not re.match(r'^[a-z]\w{0,9}$', username):
            return ""
        return username

    async def check_password(self) -> dict:
        """ Get password from post data, and check is correct """
        data = await self.request.post()
        row_password = data.get('password', '')
        if not re.match(r'^[a-z]\w{0,9}$', row_password):
            return {}
        else:
            salt = os.urandom(32)
            password = hashlib.pbkdf2_hmac('sha256', row_password.encode('utf-8'), salt, 100000)
        return {salt: password}

    def login(self, user: User):
        self.request.session["user_id"] = user.id
        self.request.session["time"] = str(datetime.datetime.now())

        redirect(self.request, "home")

    async def post(self):
        username = await self.check_username()
        password = await self.check_password()
        print('username', username, password)

        if not username or not password:
            redirect(self.request, "register")

        try:
            await User.get(username=username)
            # Такой пользователь уже есть!
            redirect(self.request, "login")
        except:
            print("Пользователя нет!")

        await User.create(username=username, password=password)
        user = await User.get(username=username, password=password)

        self.login(user)


class Logout(web.View):

    @login_required
    async def get(self):
        self.request.session.pop("user_id")
        redirect(self.request, "home")

