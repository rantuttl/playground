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

import sys
import logging

from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.v1 import configure, initialize
from api.v1.auth import RootHandler, PasswordHandler, SignupHandler

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                    format='%(asctime)s %(message)s')


def setup_server():
    tornado_logger = logging.getLogger('tornado.curl_httpclient')
    tornado_logger.addHandler(logging.NullHandler())
    tornado_logger.propagate = False

    settings = dict(
        secret='abcde12345'
    )
    configure(settings)
    IOLoop.current().add_future(initialize(settings), start_server)


def start_server(future):
    settings = future.result()

    handlers = [
        (r"/api/v1/users", RootHandler),
        (r"/api/v1/auth/signup", SignupHandler),
        (r"/api/v1/auth/login", PasswordHandler)
    ]
    application = Application(handlers, **settings)

    server = HTTPServer(application)
    server.listen(8888)


def main():
    setup_server()
    IOLoop.current().start()


if __name__ == '__main__':
    main()
