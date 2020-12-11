# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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


from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.federation.federation_base import event_from_pdu_json
from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.unittest import HomeserverTestCase


class ExtremPruneTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.state = self.hs.get_state_handler()
        self.persistence = self.hs.get_storage().persistence
        self.store = self.hs.get_datastore()

        self.register_user("user", "pass")
        token = self.login("user", "pass")

        self.room_id = self.helper.create_room_as(
            "user", room_version=RoomVersions.V6.identifier, tok=token
        )

        body = self.helper.send(self.room_id, body="Test", tok=token)
        local_message_event_id = body["event_id"]

        # Fudge a remote event an persist it. This will be the extremity before
        # the gap.
        self.remote_event_1 = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "state_key": "@user:other",
                "content": {},
                "room_id": self.room_id,
                "sender": "@user:other",
                "depth": 5,
                "prev_events": [local_message_event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        self.persist_event(self.remote_event_1)

        # Check that the current extremities is the remote event.
        self.assert_extremities([self.remote_event_1.event_id])

    def persist_event(self, event, state=None):
        """Persist the event, with optional state
        """
        context = self.get_success(
            self.state.compute_event_context(event, old_state=state)
        )
        self.get_success(self.persistence.persist_event(event, context))

    def assert_extremities(self, expected_extremities):
        """Assert the current extremities for the room
        """
        extremities = self.get_success(
            self.store.get_prev_events_for_room(self.room_id)
        )
        self.assertCountEqual(extremities, expected_extremities)

    def test_prune_gap(self):
        """Test that we drop extremities after a gap when we see an event from
        the same domain.
        """

        # Fudge a second event which points to an event we don't have. This is a
        # state event so that the state changes (otherwise we won't prune the
        # extremity as they'll have the same state group).
        remote_event_2 = event_from_pdu_json(
            {
                "type": EventTypes.Member,
                "state_key": "@user:other",
                "content": {"membership": Membership.JOIN},
                "room_id": self.room_id,
                "sender": "@user:other",
                "depth": 10,
                "prev_events": ["$some_unknown_message"],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        state_before_gap = self.get_success(self.state.get_current_state(self.room_id))

        self.persist_event(remote_event_2, state=state_before_gap.values())

        # Check the new extremity is just the new remote event.
        self.assert_extremities([remote_event_2.event_id])

    def test_do_not_prune_gap_if_state_different(self):
        """Test that we don't prune extremities after a gap if the resolved
        state is different.
        """

        # Fudge a second event which points to an event we don't have.
        remote_event_2 = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "state_key": "@user:other",
                "content": {},
                "room_id": self.room_id,
                "sender": "@user:other",
                "depth": 10,
                "prev_events": ["$some_unknown_message"],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            RoomVersions.V6,
        )

        # Now we persist it with state with a dropped history visibility
        # setting. The state resolution across the old and new event will then
        # include it, and so the resolved state won't match the new state.
        state_before_gap = dict(
            self.get_success(self.state.get_current_state(self.room_id))
        )
        state_before_gap.pop(("m.room.history_visibility", ""))

        context = self.get_success(
            self.state.compute_event_context(
                remote_event_2, old_state=state_before_gap.values()
            )
        )

        self.get_success(self.persistence.persist_event(remote_event_2, context))

        # Check that we haven't dropped the old extremity.
        self.assert_extremities([self.remote_event_1.event_id, remote_event_2.event_id])
