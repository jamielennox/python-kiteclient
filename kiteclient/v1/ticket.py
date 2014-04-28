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
import datetime
import struct

from Crypto import Random

from kiteclient.openstack.common.crypto import utils as cryptoutils
from kiteclient.openstack.common import jsonutils
from kiteclient.openstack.common import timeutils


class _TicketRequest(object):

    def __init__(self, source, destination, timestamp=None, nonce=None):
        self.source = source
        self.destination = destination
        self.timestamp = timestamp or timeutils.utcnow()
        self.nonce = nonce = nonce or self.gen_nonce()

    def get_data(self):
        return {'source': self.source,
                'destination': self.destination,
                'timestamp': timeutils.strtime(self.timestamp),
                'nonce': self.nonce}

    def encode(self):
        return base64.b64encode(jsonutils.dumps(self.get_data()))

    def generate(self, key):
        crypto = cryptoutils.SymmetricCrypto()
        metadata = self.encode()
        signature = crypto.sign(key, metadata, b64encode=True)
        return {'metadata': metadata, 'signature': signature}

    @classmethod
    def gen_nonce(cls):
        return struct.unpack('Q', Random.new().read(8))[0]


class Esek(object):

    def __init__(self, key, data, source, destination):
        self.crypto = cryptoutils.SymmetricCrypto()
        data = jsonutils.loads(self.crypto.decrypt(key, data, b64decode=True))

        base_key = base64.b64decode(data['key'])
        time_str = data['timestamp']
        info = "%s,%s,%s" % (source, destination, time_str)
        key_data = cryptoutils.HKDF().expand(base_key, info, 32)

        timestamp = timeutils.parse_strtime(time_str)
        ttl = datetime.timedelta(seconds=data['ttl'])

        self.expiration = timestamp + ttl
        self.skey = key_data[:16]
        self.ekey = key_data[16:]

    def verify(self):
        assert timeutils.utcnow() < self.expiration

    def decode(self, data, signature):
        computed_sig = self.crypto.sign(self.skey, data, b64encode=True)
        assert signature == computed_sig

        return self.crypto.decrypt(self.ekey, data, b64decode=True)


class Ticket(object):

    def __init__(self, key, metadata, ticket, signature):
        self.crypto = cryptoutils.SymmetricCrypto()

        self.b64_metadata = metadata
        self.b64_ticket = ticket
        self.b64_signature = signature

        metadata = jsonutils.loads(base64.b64decode(metadata))

        if metadata['encryption']:
            ticket = self.crypto.decrypt(key, ticket, b64decode=True)
        else:
            ticket = base64.b64decode(ticket)

        ticket = jsonutils.loads(ticket)

        self.source = metadata['source']
        self.destination = metadata['destination']
        self.expiration = timeutils.parse_strtime(metadata['expiration'])

        self.skey = base64.b64decode(ticket['skey'])
        self.ekey = base64.b64decode(ticket['ekey'])
        self.b64_esek = ticket['esek']

    @classmethod
    def create(cls, s, source, destination, src_key,
               timestamp=None, nonce=None):
        req = _TicketRequest(source=source,
                             destination=destination,
                             timestamp=timestamp,
                             nonce=nonce)

        resp = s.post('/tickets',
                      endpoint_filter={'service_type': 'kds'},
                      headers={'Accept': 'application/json'},
                      json=req.generate(src_key))

        assert resp.status_code == 200
        return Ticket(src_key, **resp.json())

    def encode(self, data, b64encode=True):
        crypto = cryptoutils.SymmetricCrypto()

        enc = crypto.encrypt(self.ekey, data, b64encode=b64encode)
        sig = crypto.sign(self.skey, enc, b64encode=b64encode)

        return enc, sig

    def verify(self, key):
        computed_sig = self.crypto.sign(key,
                                        self.b64_metadata + self.b64_ticket,
                                        b64encode=True)

        assert self.b64_signature == computed_sig

        assert timeutils.utcnow() < self.expiration
