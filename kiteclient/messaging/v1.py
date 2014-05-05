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

from oslo.config import cfg
from oslo.messaging.rpc import protocol

_kds_messaging_opts = [
    cfg.StrOpt('url', help='The URL of the Key Distribution Server'),
    cfg.StrOpt('sender', help='The name of this node for RPC'),
    cfg.StrOpt('key', help='The Base64 encode long term key'),
]


class KiteRPC(protocol.OpenStackRPC2):

    def __init__(self, conf):
        super(KiteRPC, self).__init__(conf)
        self.register_conf_opts(conf)

    @staticmethod
    def register_conf_otps(conf):
        conf.register_opts(_kds_messaging_opts)

    def serialize_msg(self, msg):
        return super(KiteRPC, self).serialize_msg(msg)

    def deserialize_msg(self, msg):
        return super(KiteRPC, self).deserialize_msg(msg)

    def serialize_exception(self, failure_info, log_failure=True):
        return super(KiteRPC, self).serialize_exception(failure_info,
                                                        log_failure)

    def deserialize_exception(self, data, allowed_remote_exmods):
        return super(KiteRPC, self).deserialize_exception(
            data, allowed_remote_exmods)
