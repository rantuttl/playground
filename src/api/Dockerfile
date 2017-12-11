# Copyright 2017-2018 rantuttl All rights reserved.
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

#FROM rtuttle/python-build:latest
FROM python:2.7.13

ADD requirements.txt requirements.txt

RUN pip install --no-cache-dir -U -r requirements.txt && \
    pip install --no-cache-dir pyinstaller

# Commented for now since we are not building from alpine image due to bootloader issues
#RUN apk add --no-cache bash

COPY . /code

# Install the api server package
RUN cd /code && pip install --no-cache-dir .
