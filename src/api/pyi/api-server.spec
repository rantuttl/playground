# -*- mode: python -*-
# -*- coding: utf-8 -*-
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
from PyInstaller.utils.hooks import copy_metadata
import re

block_cipher = None

extra_files = [('../version.txt', '')]

# 'api' should match the 'name' as specified in the setup.py file
# get metadata from needed packages, including our own.
extra_files += copy_metadata("api")
with open("../requirements.txt") as reqs:
    for line in reqs:
        m = re.match(r'^((?:[-_]|\w)+)', line)
        if m:
            print "Adding dependency files", m.group(1)
            extra_files += copy_metadata(m.group(1))

extra_binaries = []

hidden_imports = []

# verbose STDOUT for module imports during bootloading
options = [ ('v', None, 'OPTION') ]
#options = []

a = Analysis([os.path.join(HOMEPATH,'api/pyilauncher.py')],
             pathex=['/code/pyi'],
             binaries=extra_binaries,
             datas=extra_files,
             hiddenimports=hidden_imports,
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          options,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='api-server',
          debug=True,
          strip=False,
          upx=True,
          console=True )
