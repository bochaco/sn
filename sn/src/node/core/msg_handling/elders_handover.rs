// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use sn_membership::{Ballot, Handover, Membership, Reconfig, SignedVote};
use std::collections::BTreeSet;
use tiny_keccak::{Hasher, Sha3};
use xor_name::XorName;

use crate::elder_count;
use crate::messaging::{
    system::{KeyedSig, MembershipState, NodeState, RelocateDetails, SectionAuth},
    SectionAuthorityProvider,
};
use crate::node::{
    api::cmds::Cmd,
    core::relocation::{find_nodes_to_relocate, ChurnId, RelocateDetailsUtils},
    ed25519::Digest256,
    Event, Peer, Result, MIN_ADULT_AGE,
};
use crate::types::log_markers::LogMarker;

use super::Core;

impl Core {
    #[instrument(skip(self), level = "trace")]
    pub(crate) async fn handle_elders_handover_msg(
        &self,
        signed_vote: SignedVote<SignedVote<NodeState>>,
    ) -> Result<Vec<Cmd>> {
        debug!("{}", LogMarker::EldersHandoverpMsg);
        unimplemented!();
        /*
        // Before we handle the signed vote msg, let's verify we are ok with voting as well
        if !self.do_we_agree_with_msg(&signed_vote).await {
            return Ok(vec![]);
        }

        let mut state = self.elders_handover_voting.write().await;
        let prev_generation = state.gen;

        match state.handle_signed_vote(signed_vote) {
            Ok(msg_to_broadcast) => {
                let mut commands = vec![];
                if let Some(signed_vote) = msg_to_broadcast {
                    commands.extend(self.broadcast_elders_handover_vote_msg(signed_vote).await);
                }

                // If there is a new generation, it means a new consensus has been achieved
                let new_generation = state.gen;
                if new_generation != prev_generation {
                    commands.extend(self.handle_elders_handover_consensus(&state).await);
                }

                Ok(commands)
            }
            Err(err) => {
                error!(">>> Failed to handle Elders hand over Vote msg: {:?}", err);
                Ok(vec![])
            }
        }
        */
    }

    // Private helper to check if we agree with reconfigs in an incoming signed_vote msg
    async fn do_we_agree_with_msg(&self, signed_vote: &SignedVote<Reconfig<NodeState>>) -> bool {
        unimplemented!();
    }

    async fn handle_elders_handover_consensus(
        &self,
        state: &Handover<SectionAuth<SectionAuthorityProvider>>,
    ) -> Vec<Cmd> {
        self.log_section_stats().await;

        unimplemented!();
    }
}
