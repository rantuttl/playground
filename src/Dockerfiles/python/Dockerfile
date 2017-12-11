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
FROM rtuttle/base-build

RUN apk --no-cache add \
    python2 \
    py2-pip \
    python2-dev \
    ncurses-dev \
    musl-dev \
    bzip2-dev \
    libffi-dev \
    openssl-dev \
    # Compile time dependencies
    gcc \

    # General purpose dependencies
    git

# Make sure pip is at it's latest version
RUN pip install --upgrade pip

# # Create a symbolic link for musl static library inside ldd (this avoids wrapping ldd) -- DOESN'T WORK YET
#RUN ln -s /lib/libc.musl-x86_64.so.1 ldd
#RUN ln -s /lib /lib64
COPY ldd  /usr/local/bin/
RUN chmod +x /usr/local/bin/ldd

RUN pip install --no-cache-dir pyinstaller
# Manually install pyinstaller and configure it for the local context
#RUN git clone https://github.com/pyinstaller/pyinstaller.git /tmp/pyinstaller \
#    && cd /tmp/pyinstaller \
#    && git checkout 094f559092c6b529eeeaca0eb7833878899a6844 \
#    && cd /tmp/pyinstaller/bootloader \
#    && python ./waf configure all \
#    && pip install .. \
#    && rm -Rf /tmp/pyinstaller

# Start the future container in python2 shell
CMD ["python2"]
