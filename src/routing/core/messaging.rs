// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use super::Core;
use crate::messaging::{
    node::{
        DkgKey, DstInfo, ElderCandidates, JoinResponse, Network, NodeMsg, NodeState, Peer,
        PlainMessage, Proposal, RelocateDetails, RelocatePromise, Section, SectionSigned,
    },
    DstLocation, WireMsg,
};
use crate::routing::{
    dkg::{DkgKeyUtils, ProposalUtils, SigShare},
    error::Result,
    messages::WireMsgUtils,
    network::NetworkUtils,
    peer::PeerUtils,
    relocation::RelocateState,
    routing_api::command::Command,
    section::{ElderCandidatesUtils, SectionAuthorityProviderUtils, SectionKeyShare, SectionUtils},
};
use bls::PublicKey as BlsPublicKey;
use secured_linked_list::SecuredLinkedList;
use std::{cmp::Ordering, iter, net::SocketAddr, slice};
use xor_name::XorName;

impl Core {
    // Send proposal to all our elders.
    pub(crate) fn propose(&self, proposal: Proposal) -> Result<Vec<Command>> {
        let elders: Vec<_> = self.section.authority_provider().peers().collect();
        self.send_proposal(&elders, proposal)
    }

    // Send `proposal` to `recipients`.
    pub(crate) fn send_proposal(
        &self,
        recipients: &[Peer],
        proposal: Proposal,
    ) -> Result<Vec<Command>> {
        let key_share = self.section_keys_provider.key_share().map_err(|err| {
            trace!("Can't propose {:?}: {}", proposal, err);
            err
        })?;
        self.send_proposal_with(recipients, proposal, key_share)
    }

    pub(crate) fn send_proposal_with(
        &self,
        recipients: &[Peer],
        proposal: Proposal,
        key_share: &SectionKeyShare,
    ) -> Result<Vec<Command>> {
        trace!(
            "Propose {:?}, key_share: {:?}, aggregators: {:?}",
            proposal,
            key_share,
            recipients,
        );

        let sig_share = proposal.prove(
            key_share.public_key_set.clone(),
            key_share.index,
            &key_share.secret_key_share,
        )?;

        // Broadcast the proposal to the rest of the section elders.
        let node_msg = NodeMsg::Propose {
            content: proposal,
            sig_share,
        };
        let wire_msg = WireMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted(*self.section.chain().last_key()),
            node_msg,
            self.section.authority_provider().section_key(),
        )?;

        Ok(self.send_or_handle(wire_msg, recipients))
    }

    // ------------------------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------------------------

    pub(crate) fn check_lagging(
        &self,
        peer: (XorName, SocketAddr),
        sig_share: &SigShare,
    ) -> Result<Option<Command>> {
        let public_key = sig_share.public_key_set.public_key();

        if self.section.chain().has_key(&public_key)
            && public_key != *self.section.chain().last_key()
        {
            // The key is recognized as non-last, indicating the peer is lagging.
            Ok(Some(self.send_direct_message(
                peer,
                // TODO: consider sending only those parts of section that are new
                // since `public_key` was the latest key.
                NodeMsg::Sync {
                    section: self.section.clone(),
                    network: self.network.clone(),
                },
                sig_share.public_key_set.public_key(),
            )?))
        } else {
            Ok(None)
        }
    }

    // Send NodeApproval to a joining node which makes them a section member
    pub(crate) fn send_node_approval(
        &self,
        node_state: SectionSigned<NodeState>,
    ) -> Result<Command> {
        info!(
            "Our section with {:?} has approved peer {:?}.",
            self.section.prefix(),
            node_state.value.peer
        );

        let addr = *node_state.value.peer.addr();
        let name = *node_state.value.peer.name();

        let node_msg = NodeMsg::JoinResponse(Box::new(JoinResponse::Approval {
            genesis_key: *self.section.genesis_key(),
            section_auth: self.section.section_signed_authority_provider().clone(),
            node_state,
            section_chain: self.section.chain().clone(),
        }));

        let wire_msg = WireMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted(*self.section.chain().last_key()),
            node_msg,
            self.section.authority_provider().section_key(),
        )?;

        Ok(Command::send_message_to_node((name, addr), wire_msg))
    }

    pub(crate) fn send_sync(&mut self, section: Section, network: Network) -> Result<Vec<Command>> {
        let send = |node_msg, recipients: Vec<(XorName, SocketAddr)>| -> Result<_> {
            trace!("Send {:?} to {:?}", node_msg, recipients);

            let wire_msg = WireMsg::single_src(
                &self.node,
                DstLocation::DirectAndUnrouted(*self.section_chain().last_key()),
                node_msg,
                self.section.authority_provider().section_key(),
            )?;

            Ok(Command::send_message_to_nodes(
                recipients.clone(),
                recipients.len(),
                wire_msg,
            ))
        };

        let mut commands = vec![];

        let (elders, non_elders): (Vec<_>, _) = section
            .active_members()
            .filter(|peer| peer.name() != &self.node.name())
            .map(|peer| (*peer.name(), *peer.addr()))
            .partition(|peer| section.is_elder(&peer.0));

        // Send the trimmed state to non-elders. The trimmed state contains only the knowledge of
        // own section.
        let node_msg = NodeMsg::Sync {
            section: section.clone(),
            network: Network::new(),
        };
        commands.push(send(node_msg, non_elders)?);

        // Send the full state to elders.
        // The full state contains the whole section chain.
        let node_msg = NodeMsg::Sync { section, network };
        commands.push(send(node_msg, elders)?);

        Ok(commands)
    }

    pub(crate) fn send_sync_to_adults(&mut self) -> Result<Vec<Command>> {
        let send = |node_msg, recipients: Vec<_>| -> Result<_> {
            trace!("Send {:?} to {:?}", node_msg, recipients);

            let wire_msg = WireMsg::single_src(
                &self.node,
                DstLocation::DirectAndUnrouted(*self.section_chain().last_key()),
                node_msg,
                self.section.authority_provider().section_key(),
            )?;

            Ok(Command::send_message_to_nodes(
                recipients.clone(),
                recipients.len(),
                wire_msg,
            ))
        };

        let mut commands = vec![];

        let adults: Vec<_> = self
            .section
            .live_adults()
            .map(|peer| (*peer.name(), *peer.addr()))
            .collect();

        let node_msg = NodeMsg::Sync {
            section: self.section.clone(),
            network: Network::new(),
        };

        commands.push(send(node_msg, adults)?);

        Ok(commands)
    }

    pub(crate) fn send_relocate(
        &self,
        recipient: &Peer,
        details: RelocateDetails,
    ) -> Result<Vec<Command>> {
        let src = details.pub_id;
        let dst = DstLocation::Node {
            name: details.pub_id,
            section_pk: *self.section.chain().last_key(),
        };
        let node_msg = NodeMsg::Relocate(details);

        self.send_message_for_dst_accumulation(src, dst, node_msg, slice::from_ref(recipient))
    }

    pub(crate) fn send_relocate_promise(
        &self,
        recipient: &Peer,
        promise: RelocatePromise,
    ) -> Result<Vec<Command>> {
        // Note: this message is first sent to a single node who then sends it back to the section
        // where it needs to be handled by all the elders. This is why the destination is
        // `Section`, not `Node`.
        let src = promise.name;
        let dst = DstLocation::Section {
            name: promise.name,
            section_pk: *self.section.chain().last_key(),
        };
        let node_msg = NodeMsg::RelocatePromise(promise);

        self.send_message_for_dst_accumulation(src, dst, node_msg, slice::from_ref(recipient))
    }

    pub(crate) fn return_relocate_promise(&self) -> Option<Command> {
        // TODO: keep sending this periodically until we get relocated.
        if let Some(RelocateState::Delayed(msg)) = &self.relocate_state {
            self.send_message_to_our_elders(msg.clone()).ok()
        } else {
            None
        }
    }

    pub(crate) fn send_dkg_start(&self, elder_candidates: ElderCandidates) -> Result<Vec<Command>> {
        // Send to all participants.
        let recipients: Vec<_> = elder_candidates.peers().collect();
        self.send_dkg_start_to(elder_candidates, &recipients)
    }

    pub(crate) fn send_dkg_start_to(
        &self,
        elder_candidates: ElderCandidates,
        recipients: &[Peer],
    ) -> Result<Vec<Command>> {
        let src_prefix = elder_candidates.prefix;
        let generation = self.section.chain().main_branch_len() as u64;
        let dkg_key = DkgKey::new(&elder_candidates, generation);

        trace!(
            "Send DkgStart for {:?} with {:?} to {:?}",
            elder_candidates,
            dkg_key,
            recipients
        );

        let node_msg = NodeMsg::DkgStart {
            dkg_key,
            elder_candidates,
        };

        self.send_message_for_dst_accumulation(
            src_prefix.name(),
            DstLocation::DirectAndUnrouted(*self.section.chain().last_key()),
            node_msg,
            recipients,
        )
    }

    pub(crate) fn create_aggregate_at_src_proposal(
        &self,
        dst: DstLocation,
        node_msg: NodeMsg,
        proof_chain_first_key: Option<&BlsPublicKey>,
    ) -> Result<Proposal> {
        let proof_chain = self.create_proof_chain(proof_chain_first_key)?;
        let dst_key = if let Some(name) = dst.name() {
            self.section_key_by_name(&name)
        } else {
            // NOTE: `dst` is `Direct`. We use this when we want the message to accumulate at the
            // destination and also be handled only there. We only do this if the recipient is in
            // our section, so it's OK to use our latest key as the `dst_key`.
            *self.section.chain().last_key()
        };

        let message = PlainMessage {
            src: self.section.prefix().name(),
            dst,
            dst_key,
            node_msg,
        };

        let proposal = Proposal::AccumulateAtSrc {
            message: Box::new(message),
            proof_chain,
        };
        trace!("Created aggregate at source proposal {:?}", proposal);
        Ok(proposal)
    }

    pub(crate) fn send_message_for_dst_accumulation(
        &self,
        src: XorName,
        dst: DstLocation,
        node_msg: NodeMsg,
        recipients: &[Peer],
    ) -> Result<Vec<Command>> {
        let key_share = self.section_keys_provider.key_share().map_err(|err| {
            trace!(
                "Can't create message {:?} for accumulation at dst {:?}: {}",
                node_msg,
                dst,
                err
            );
            err
        })?;

        let wire_msg = WireMsg::for_dst_accumulation(
            key_share,
            src,
            dst,
            node_msg,
            self.section.chain().clone(),
        )?;

        trace!(
            "Send {:?} for accumulation at dst to {:?}",
            wire_msg,
            recipients
        );

        Ok(self.send_or_handle(wire_msg, recipients))
    }

    // Send the message to all `recipients`. If one of the recipients is us, don't send it over the
    // network but handle it directly.
    pub(crate) fn send_or_handle(
        &self,
        mut wire_msg: WireMsg,
        recipients: &[Peer],
    ) -> Vec<Command> {
        let mut commands = vec![];
        let mut others = Vec::new();
        let mut handle = false;

        trace!("Send {:?} to {:?}", wire_msg, recipients);

        for recipient in recipients {
            if recipient.name() == &self.node.name() {
                handle = true;
            } else {
                others.push((*recipient.name(), *recipient.addr()));
            }
        }

        if !others.is_empty() {
            let count = others.len();
            let dst_section_pk = self.section_key_by_name(&others[0].0);
            wire_msg.set_dst_section_pk(dst_section_pk);
            commands.push(Command::send_message_to_nodes(
                others,
                count,
                wire_msg.clone(),
            ));
        }

        if handle {
            wire_msg.set_dst_section_pk(*self.section_chain().last_key());
            wire_msg.set_dst_xorname(self.node.name());

            commands.push(Command::HandleMessage {
                sender: self.node.addr,
                wire_msg,
            });
        }

        commands
    }

    pub(crate) fn create_proof_chain(
        &self,
        additional_key: Option<&BlsPublicKey>,
    ) -> Result<SecuredLinkedList> {
        // The last key of the signed chain is the last section key for which we also have the
        // secret key share. Ideally this is our current section key unless we haven't observed the
        // DKG completion yet.
        let last_key = self
            .section_keys_provider
            .key_share()?
            .public_key_set
            .public_key();

        // Only include `additional_key` if it is older than `last_key` because `last_key` must be
        // the actual last key of the resulting signed chain because it's the key that will be used
        // to sign the message.
        let additional_key = additional_key
            .filter(|key| self.section.chain().cmp_by_position(key, &last_key) == Ordering::Less);

        Ok(self
            .section
            .chain()
            .minimize(iter::once(&last_key).chain(additional_key))?)
    }

    pub(crate) fn send_direct_message(
        &self,
        recipient: (XorName, SocketAddr),
        node_msg: NodeMsg,
        dst_pk: BlsPublicKey,
    ) -> Result<Command> {
        let wire_msg = WireMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted(dst_pk),
            node_msg,
            self.section.authority_provider().section_key(),
        )?;

        Ok(Command::send_message_to_node(recipient, wire_msg))
    }

    // TODO: consider changing this so it sends only to a subset of the elders
    // (say 1/3 of the ones closest to our name or so)
    pub(crate) fn send_message_to_our_elders(&self, node_msg: NodeMsg) -> Result<Command> {
        let targets: Vec<_> = self
            .section
            .authority_provider()
            .elders()
            .iter()
            .map(|(name, address)| (*name, *address))
            .collect();

        let dst_section_pk = *self.section_chain().last_key();
        let wire_msg = WireMsg::single_src(
            &self.node,
            DstLocation::DirectAndUnrouted(dst_section_pk),
            node_msg,
            self.section.authority_provider().section_key(),
        )?;

        Ok(Command::send_message_to_nodes(
            targets.clone(),
            targets.len(),
            wire_msg,
        ))
    }
}
