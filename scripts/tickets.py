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

src = v1.Key.generate('testsrc')
src.create(s)

print "Created Key: %s:%s" % (src.name, src.generation)

dest = v1.Key.generate('testdest')
dest.create(s)

print "Created Key: %s:%s" % (dest.name, dest.generation)

ticket = v1.Ticket.create(s,
                          source=src.name,
                          destination=dest.name,
                          src_key=base64.b64decode(src.key))

esek = v1.Esek(base64.b64decode(dest.key),
               ticket.b64_esek,
               source=ticket.source,
               destination=ticket.destination)

print "rndkey: %s, skey: %s, ekey: %s" % (base64.b64encode(esek.rndkey),
                                          base64.b64encode(esek.skey),
                                          base64.b64encode(esek.ekey))

raw_data = "hello world"
enc_data, sig = ticket.encode(raw_data)
unenc_data = esek.decode(enc_data, sig)

assert raw_data == unenc_data
