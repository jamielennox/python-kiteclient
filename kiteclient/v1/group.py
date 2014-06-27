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

from kiteclient.common import resource
from kiteclient.openstack.common import jsonutils
from kiteclient.openstack.common import timeutils
from kiteclient.v1 import ticket


class Group(resource.Resource):

    base_path = 'groups'

    def __init__(self, name, source, session=None):
        self.name = name
        self.source = source
        self.key_data = {}

        if session:
            self.create(session)

    def create(self, session):
        resp = self._http_put(session, self.name).json()

        if resp['name'] != self.name:
            raise RuntimeError('Service returned invalid group name')

    def _fetch_key(self, session, generation,
                   timestamp=None, nonce=None, b64encode=True):
        name = '%s:%d' % (self.name, generation)
        b64_metadata = ticket._Metadata(self.source.name, name).encode()
        b64_signature = self.source.sign(b64_metadata, b64encode=True)

        json = {'metadata': b64_metadata, 'signature': b64_signature}

        resp = self._http_post(session, json=json).json()

        b64_metadata = resp['metadata']
        b64_groupkey = resp['group_key']
        b64_signature = resp['signature']

        sig = self.source.sign(b64_metadata + b64_groupkey, b64encode=True)

        if sig != b64_signature:
            raise ValueError("invalid signature on group key")

        metadata = jsonutils.loads(base64.b64decode(b64_metadata))

        if metadata['source'] != self.source.key_name:
            raise ValueError("invalid source on group key")

        destination, new_generation = metadata['destination'].split(':')

        if destination != name:
            raise ValueError("invalid source on group key")
        if new_generation != generation:
            raise ValueError("wrong generation returned for group key")

        data = self.source.decrypt(b64_groupkey, b64decode=True)
        expiration = timeutils.parse_strtime(metadata['expiration'])

        return data, expiration

    def get_key(self, session, generation,
                timestamp=None, nonce=None, b64encode=True):
        try:
            key, expiration = self.key_data[generation]
        except KeyError:
            key, expiration = self._fetch_key(session, generation,
                                              timestamp=timestamp, nonce=nonce)
            self.key_data[generation] = (key, expiration)

        if timeutils.utcnow() > expiration:
            raise ValueError("returned key is expired")

        if b64encode:
            key = base64.b64encode(key)

        return key
