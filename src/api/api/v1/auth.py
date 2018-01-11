"""
Copyright 2017-2018 rantuttl All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import jwt
import json
import logging
import random
import uuid
import string

from datetime import datetime, timedelta
from tornado.gen import coroutine, Return
from tornado.web import RequestHandler, HTTPError
from passlib.hash import sha512_crypt

from api.v1 import TOKEN_HEADER, VALIDATION_TOKEN_HEADER


ROUNDS = 40000

user_cache = dict()


def _generate_hashed_password(password):
    salt = "".join(random.SystemRandom().choice(string.ascii_uppercase
                   + string.digits) for _ in range(64))
    hash = sha512_crypt.encrypt((password + salt).encode("utf-8"),
                                rounds=ROUNDS)
    hash_parts = hash.split("$rounds={0}$".format(ROUNDS))
    return {"hash": hash_parts[1],
            "rounds": "{0}$rounds={1}$".format(hash_parts[0], ROUNDS),
            "salt": salt}


def _fill_signup_invitation_request(document, firstname, lastname,
                                    password=None):
    document["firstname"] = firstname
    document["lastname"] = lastname
    document["email_validated_at"] = datetime.utcnow()
    if password is not None:
        document["password"] = _generate_hashed_password(password)


class RootHandler(RequestHandler):

    @coroutine
    def get(self):
        try:
            users = json.dumps(user_cache)
        except Exception:
            raise HTTPError(500, message='JSON encode failure')
        else:
            self.write(users)
            self.flush()


class AuthHandler(RequestHandler):

    @coroutine
    def authenticate_user(self, user):
        logging.info("Authenticating user '%(username)s'", user)

        token = dict(
            id=str(user["_id"]),
            username=user["username"],
            firstname=user["firstname"],
            lastname=user["lastname"],
            email=user["email"],
            role=user["role"],
            created=datetime.utcnow().isoformat(),
            exp=datetime.utcnow() + timedelta(30)
        )

        user["last_login"] = datetime.utcnow().isoformat()
        #yield self.settings["database"].Users.update({"_id": user["_id"]}, user)

        token = jwt.encode(token, self.settings["secret"], algorithm="HS256")
        self.set_cookie(TOKEN_HEADER, token)

        logging.info("User '%(username)s' authenticated.", user)
        raise Return(token)


class PasswordHandler(AuthHandler):

    @coroutine
    def post(self):
        logging.info("Initiating PasswordHandler post")

        data = json.loads(self.request.body)
        if "username" not in data:
            raise HTTPError(400, reason="Missing username in body request.")

        if "password" not in data:
            raise HTTPError(400, reason="Missing password in body request.")

        username = data["username"]
        password = data["password"]

        #user = yield self.settings["database"].Users.find_one({"username": username})
        user = user_cache.get(username)
        if not user:
            logging.info("Username '%s' not found.", username)
            raise HTTPError(302, reason='/request-invite')

        if 'email_validated_at' not in user:
            logging.info("Username '%s' not validated.", username)
            raise HTTPError(302, reason='/request-invite')

        if 'password' not in user:
            logging.info("User '%s' has not password.", username)
            raise HTTPError(401, reason="Invalid username or password.")

        encoded_user_password = '{0}{1}'.format(user["password"]["rounds"],
                                                user["password"]["hash"])
        if sha512_crypt.verify((password
                               + user["password"]["salt"]).encode("utf-8"),
                               encoded_user_password):
            token = yield self.authenticate_user(user)
            self.write(token)
            self.flush()
        else:
            logging.info("Invalid password for user '%s'.", username)
            raise HTTPError(401, reason="Invalid username or password.")


class SignupHandler(AuthHandler):

    @staticmethod
    def _validate_signup_data(data):
        if "email" not in data:
            raise HTTPError(400, reason="Email is required.")

        if "password" not in data:
            raise HTTPError(400, reason="Password is required.")

        if "firstname" not in data:
            raise HTTPError(400, reason="First name is required.")

        if "lastname" not in data:
            raise HTTPError(400, reason="Last name is required.")

        return True

    @coroutine
    def _update_invited_user(self, validation_token, data):
        #user = yield Query(self.settings["database"], "Users").find_one(
        #    {"invite_token": validation_token, "email": data["email"]})
        user = user_cache.get(data["email"])

        if user is not None and "email_validated_at" not in user:
            #for namespace_name in user["namespaces"]:
            #    namespace = yield Query(self.settings["database"], "Namespaces").find_one({"name": namespace_name})
            #    if namespace is None:
            #        logging.warn("Cannot find namespace %s", namespace_name)
            #    else:
            #        if "members" in namespace:
            #            namespace["members"].append(user["username"])
            #        else:
            #            namespace["members"] = [user["username"]]

            #        yield Query(self.settings["database"], "Namespaces").update(namespace)

            #del user["namespaces"]

            _fill_signup_invitation_request(
                user, firstname=data["firstname"], lastname=data["lastname"],
                password=data["password"])

            raise Return(user)
        else:
            raise HTTPError(403, message="Invitation not found.")

    @coroutine
    def post(self):
        try:
            data = json.loads(self.request.body)
        except Exception:
            raise HTTPError(400, message='Invalid JSON')

        validation_token = self.request.headers.get(VALIDATION_TOKEN_HEADER)
        if validation_token is not None:
            self._validate_signup_data(data)
            user = yield self._update_invited_user(validation_token, data)
            token = yield self.authenticate_user(user)
            self.write(token)
            self.flush()

        # Signup can be used only the first time
        #elif (yield Query(self.settings["database"], "Users").find_one()) is not None:
        #    raise HTTPError(403, message="Onboarding already completed.")

        else:
            self._validate_signup_data(data)

            user = dict(
                _id=str(uuid.uuid4()),
                email=data["email"],
                username=data["email"],
                password=_generate_hashed_password(data["password"]),
                firstname=data["firstname"],
                lastname=data["lastname"],
                role="administrator",
                schema="http://elasticbox.net/schemas/user",
                email_validated_at=datetime.utcnow().isoformat()
            )

            #signup_user = yield Query(self.settings["database"], "Users").insert(user)
            signup_user = user_cache[user["email"]] = user
            token = yield self.authenticate_user(signup_user)
            self.write(token)
            self.flush()
