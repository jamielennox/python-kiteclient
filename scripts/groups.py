# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import base64
import logging

from keystoneclient.auth import token_endpoint
from keystoneclient import session

from kiteclient import v1

logging.basicConfig(level=logging.DEBUG)

auth = token_endpoint.Token('http://localhost:9109/v1', 'aToken')
s = session.Session(auth=auth)

me = 'testgrp.hostname'

src = v1.Key.generate(me)
src.create(s)
src_key = base64.b64decode(src.key)

group = v1.Group(me.split('.')[0])
group.create(s)

key_data = group.get_key(s, me, src_key, generation=2)
print base64.b64encode(key_data)
