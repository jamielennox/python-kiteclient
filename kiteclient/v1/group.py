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

from kiteclient.openstack.common.crypto import utils as cryptoutils
from kiteclient.openstack.common import jsonutils
from kiteclient.openstack.common import timeutils
from kiteclient.v1 import resource
from kiteclient.v1 import ticket


class Group(resource.Resource):

    allow_create = True
    allow_delete = True

    base_path = 'groups'
    id_key = 'name'

    def __init__(self, name, loaded=False):
        super(Group, self).__init__(loaded=loaded)
        self.name = name
        self.key_data = {}

    @classmethod
    def create_by_id(cls, session, attrs, r_id):
        if not r_id:
            raise AttributeError('You need to have set an id for this object')

        return super(Group, cls).create_by_id(session, attrs, r_id)

    def get_key(self, s, source, src_key, generation=None,
                timestamp=None, nonce=None):
        try:
            return self.key_data[generation]
        except KeyError:
            pass

        name = '%s:%s' % (self.name, generation) if generation else self.name

        req = ticket._TicketRequest(source,
                                    name,
                                    timestamp=None,
                                    nonce=None)

        resp = self._http_post(s, '/groups', json=req.generate(src_key))
        assert resp.status_code == 200
        resp_data = resp.json()

        crypto = cryptoutils.SymmetricCrypto()
        computed = crypto.sign(src_key,
                               resp_data['metadata'] + resp_data['group_key'],
                               b64encode=True)

        assert resp_data['signature'], computed
        metadata = jsonutils.loads(base64.b64decode(resp_data['metadata']))

        expiration = timeutils.parse_strtime(metadata['expiration'])
        assert timeutils.utcnow() < expiration

        return crypto.decrypt(src_key, resp_data['group_key'])
