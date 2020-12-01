#  Copyright 2020 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from synapse.handlers.sso import MappingException

from tests.unittest import HomeserverTestCase

# These are a few constants that are used as config parameters in the tests.
BASE_URL = "https://synapse/"
SERVER_URL = "https://issuer/"


class CasHandlerTestCase(HomeserverTestCase):
    def default_config(self):
        config = super().default_config()
        config["public_baseurl"] = BASE_URL
        cas_config = {
            "enabled": True,
            "server_url": SERVER_URL,
            "service_url": BASE_URL,
        }
        config["cas_config"] = cas_config

        return config

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()

        self.handler = hs.get_cas_handler()

        # Reduce the number of attempts when generating MXIDs.
        sso_handler = hs.get_sso_handler()
        sso_handler._MAP_USERNAME_RETRIES = 3

        return hs

    def test_map_cas_user_to_user(self):
        """Ensure that mapping the CAS user returned from a provider to an MXID works properly."""
        cas_user_id = "test_user"
        display_name = ""
        mxid = self.get_success(
            self.handler._map_cas_user_to_matrix_user(
                cas_user_id, display_name, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@test_user:test")

    def test_map_cas_user_to_invalid_localpart(self):
        """CAS automaps invalid characters to base-64 encoding."""
        cas_user_id = "föö"
        display_name = ""
        mxid = self.get_success(
            self.handler._map_cas_user_to_matrix_user(
                cas_user_id, display_name, "user-agent", "10.10.10.10"
            )
        )
        self.assertEqual(mxid, "@f=c3=b6=c3=b6:test")

    def test_map_cas_user_to_user_retries(self):
        """It can retry generating an MXID if the MXID is already in use."""
        store = self.hs.get_datastore()
        self.get_success(
            store.register_user(user_id="@test_user:test", password_hash=None)
        )
        cas_user_id = "test_user"
        display_name = ""
        mxid = self.get_success(
            self.handler._map_cas_user_to_matrix_user(
                cas_user_id, display_name, "user-agent", "10.10.10.10"
            )
        )
        # test_user is already taken, so test_user1 gets registered instead.
        self.assertEqual(mxid, "@test_user1:test")

        # Register all of the potential mxids for a particular CAS username.
        self.get_success(
            store.register_user(user_id="@tester:test", password_hash=None)
        )
        for i in range(1, 3):
            self.get_success(
                store.register_user(user_id="@tester%d:test" % i, password_hash=None)
            )

        # Now attempt to map to a username, this will fail since all potential usernames are taken.
        cas_user_id = "tester"
        e = self.get_failure(
            self.handler._map_cas_user_to_matrix_user(
                cas_user_id, display_name, "user-agent", "10.10.10.10"
            ),
            MappingException,
        )
        self.assertEqual(
            str(e.value), "Unable to generate a Matrix ID from the SSO response"
        )
