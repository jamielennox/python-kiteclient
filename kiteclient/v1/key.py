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

from Crypto import Random

# from kiteclient.openstack.common.crypto import utils as cryptoutils
from kiteclient.v1 import resource


class Key(resource.Resource):

    allow_create = True
    allow_delete = True

    base_path = 'keys'
    id_key = 'name'

    key = resource.prop('key')
    generation = resource.prop('generation')

    @classmethod
    def generate(cls, name):
        new = cls()
        new.id = name
        new.key = base64.b64encode(Random.new().read(16))
        return new

    @classmethod
    def create_by_id(cls, session, attrs, r_id):
        if not r_id:
            raise AttributeError('You need to have set an id for this object')

        return super(Key, cls).create_by_id(session, attrs, r_id)

    # @classmethod
    # def sign_with_bytes(cls, key, msg, b64encode=True):
    #     c = cryptoutils.SymmetricCrypto()
    #     return c.sign(key, msg)

    # def sign(self, data, b64encode=True):
    #     return self.sign_with_key(self.key, data, b64encode=b64encode)
