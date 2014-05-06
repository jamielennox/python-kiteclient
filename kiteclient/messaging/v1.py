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

from keystoneclient import session
from keystoneclient.auth import token_endpoint
from oslo.config import cfg
from oslo.messaging.rpc import protocol

from kiteclient.openstack.common import jsonutils
from kiteclient.v1 import ticket


_kds_messaging_opts = [
    cfg.StrOpt('kds_url', help='The URL of the Key Distribution Server'),
    cfg.StrOpt('kds_sender', help='The name of this node for RPC'),
    cfg.StrOpt('kds_key', help='The Base64 encode long term key'),
]


class KiteRPC(protocol.OpenStackRPC2):

    def __init__(self, conf):
        super(KiteRPC, self).__init__(conf)
        self.register_conf_opts(conf)

        self.session = session.Session()
        self.session.auth = token_endpoint.Token(conf.url, None)
        self.sender = conf.sender

        self.key = base64.b64decode(conf.key)

    @staticmethod
    def register_conf_otps(conf):
        conf.register_opts(_kds_messaging_opts)

    def serialize_msg(self, target, msg):
        tick = ticket.Ticket.create(self.session,
                                    self.sender,
                                    target,
                                    self.key)

        data = super(KiteRPC, self).serialize_msg(msg)
        json_data = jsonutils.dumps(data)

        enc, sig = tick.encode(json_data)

        return {'data': enc,
                'signature': sig,
                'source': self.sender,
                'destination': target,
                'esek': ticket.b64_esek}

    def deserialize_msg(self, msg):
        assert msg['destination'] == self.sender

        esek = ticket.Esek(self.key, msg['esek'], msg['source'], self.sender)
        esek.verify()

        data = esek.decode(msg['data'], msg['signature'])
        return super(KiteRPC, self).deserialize_msg(data)

    def serialize_exception(self, failure_info, log_failure=True):
        return super(KiteRPC, self).serialize_exception(failure_info,
                                                        log_failure)

    def deserialize_exception(self, data, allowed_remote_exmods):
        return super(KiteRPC, self).deserialize_exception(
            data, allowed_remote_exmods)
