#!/usr/bin/env python
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

import os
import os.path
import setuptools
import inspect

def collect_requirements():

    def filter_requirements(filters, file):
        for reqfilter in filters:
            if reqfilter in file:
                return True

        return False

    reqs = set()
    # This monstrosity is the only way to definitely get the location of
    # setup.py regardless of how you execute it. It's tempting to use __file__
    # but that only works if setup.py is executed directly, otherwise it all
    # goes terribly wrong.
    directory =  os.path.dirname(
        os.path.abspath(inspect.getfile(inspect.currentframe()))
    )

    files = os.listdir(directory)
    unfiltered_reqs = (f for f in files if f.endswith('requirements.txt'))

    # If the environment variable $APIDEPS is set, only the corresponding
    # dependencies are installed.
    deps = os.environ.get('APIDEPS')
    if deps:
        filters = map(lambda s: s.lower().strip(), deps.split(','))
        requirements_files = (
             f for f in unfiltered_reqs if filter_requirements(filters, f)
        )
    else:
        requirements_files = unfiltered_reqs

    for reqfile in requirements_files:
        with open(reqfile, 'r') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if line:
                    reqs.add(line)

    return reqs



# 'name' should match the package name (directory) when 'pip install .'
# is run against this setup.py
setuptools.setup(
    name="api",
    version="0.0.1",
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'api-server = api.server:main',
        ]
    },
    scripts=[],
    install_requires=collect_requirements()
)
