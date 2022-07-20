// Copyright 2022 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::node::{flow_ctrl::FlowCtrl, messages::WireMsgUtils, Node, Peer, Result};

use sn_interface::{
    messaging::{system::SystemMsg, DstLocation, WireMsg},
    network_knowledge::SectionAuthorityProvider,
    types::log_markers::LogMarker,
};

use ed25519_dalek::PublicKey;
use secured_linked_list::SecuredLinkedList;
use std::{net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use xor_name::{Prefix, XorName};

/// Test interface for sending and receiving messages to and from other nodes.
///
/// A node is a part of the network that can route messages and be a member of a section or group
/// location. Its methods can be used to send requests and responses as either an individual
/// `Node` or as a part of a section or group location. Their `src` argument indicates that
/// role, and can be `use sn_interface::messaging::SrcLocation::Node` or `use sn_interface::messaging::SrcLocation::Section`.
#[allow(missing_debug_implementations)]
pub struct NodeTestApi {
    node: Arc<RwLock<Node>>,
    flow_ctrl: FlowCtrl,
}

impl NodeTestApi {
    pub(crate) fn new(node: Arc<RwLock<Node>>, flow_ctrl: FlowCtrl) -> Self {
        Self { node, flow_ctrl }
    }

    /// Returns the current age of this node.
    pub async fn age(&self) -> u8 {
        self.node.read().await.info().age()
    }

    /// Returns the ed25519 public key of this node.
    pub async fn public_key(&self) -> PublicKey {
        self.node.read().await.keypair.public
    }

    /// The name of this node.
    pub async fn name(&self) -> XorName {
        self.node.read().await.info().name()
    }

    /// Returns connection info of this node.
    pub async fn our_connection_info(&self) -> SocketAddr {
        self.node.read().await.info().addr
    }

    /// Returns the Section Signed Chain
    pub async fn section_chain(&self) -> SecuredLinkedList {
        self.node.read().await.section_chain()
    }

    /// Returns the Section Chain's genesis key
    pub async fn genesis_key(&self) -> bls::PublicKey {
        *self.node.read().await.network_knowledge().genesis_key()
    }

    /// Prefix of our section
    pub async fn our_prefix(&self) -> Prefix {
        self.node.read().await.network_knowledge().prefix()
    }

    /// Returns whether the node is Elder.
    pub async fn is_elder(&self) -> bool {
        self.node.read().await.is_elder()
    }

    /// Returns the information of all the current section elders.
    pub async fn our_elders(&self) -> Vec<Peer> {
        self.node.read().await.network_knowledge().elders()
    }

    /// Returns the information of all the current section adults.
    pub async fn our_adults(&self) -> Vec<Peer> {
        self.node.read().await.network_knowledge().adults()
    }

    /// Returns the info about the section matching the name.
    pub async fn matching_section(&self, name: &XorName) -> Result<SectionAuthorityProvider> {
        self.node.read().await.matching_section(name)
    }

    /// Builds a `WireMsg` signed by this Node
    pub async fn sign_single_src_msg(
        &self,
        node_msg: SystemMsg,
        dst: DstLocation,
    ) -> Result<WireMsg> {
        let src_section_pk = *self.section_chain().await.last_key();
        WireMsg::single_src(
            &self.node.read().await.info(),
            dst,
            node_msg,
            src_section_pk,
        )
    }

    /// Send a message.
    /// Messages sent here, either section to section or node to node.
    pub async fn send_msg_to_nodes(&self, wire_msg: WireMsg) -> Result<()> {
        trace!(
            "{:?} {:?}",
            LogMarker::DispatchSendMsgCmd,
            wire_msg.msg_id()
        );

        let cmds = self.node.read().await.send_msg_on_to_nodes(wire_msg)?;

        if let Some(cmd) = cmds {
            self.flow_ctrl.fire_and_forget(cmd).await?;
        }

        Ok(())
    }

    /// Returns the current BLS public key set if this node has one, or
    /// `Error::MissingSecretKeyShare` otherwise.
    pub async fn public_key_set(&self) -> Result<bls::PublicKeySet> {
        self.node.read().await.public_key_set()
    }
}