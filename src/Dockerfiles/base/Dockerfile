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
FROM alpine:3.6

# Install common dependencies for both go and python builds and make the container glibc enabled with set locales
RUN apk --no-cache --update --virtual=.fetch_deps add \
        ca-certificates \
        wget \
    && mkdir glibc \
    && wget \
        -O /etc/apk/keys/sgerrand.rsa.pub \
        https://raw.githubusercontent.com/sgerrand/alpine-pkg-glibc/master/sgerrand.rsa.pub \
        -nv \
    && wget \
        -O /glibc/glibc.apk \
        https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.25-r0/glibc-2.25-r0.apk \
        -nv \
    && wget \
        -O /glibc/glibc-bin.apk \
        https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.25-r0/glibc-bin-2.25-r0.apk \
        -nv \
    && wget \
        -O /glibc/glibc-i18n.apk \
        https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.25-r0/glibc-i18n-2.25-r0.apk \
        -nv \
    && apk --no-cache add glibc/glibc.apk glibc/glibc-bin.apk glibc/glibc-i18n.apk \
    && /usr/glibc-compat/bin/localedef -i en_US -f UTF-8 en_US.UTF-8 \
    && rm -R glibc \
    && rm /etc/apk/keys/sgerrand.rsa.pub \
    && apk del --purge .fetch_deps \
    && apk del --purge glibc-bin glibc-i18n

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US.UTF-8
