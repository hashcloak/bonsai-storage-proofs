// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![no_main]

use std::io::Read;
#[allow(unused_imports)]
use ethabi::{ethereum_types::U256, ParamType, Token};
use risc0_zkvm::guest::env;
use trie_db::{Trie, TrieDBBuilder, TrieLayout};
use hash_db::{HashDB, Hasher};
use tiny_keccak::{Keccak, Hasher as TinyKeccakHasher};
use hash256_std_hasher::Hash256StdHasher;
use std::collections::BTreeSet;
use codec::{Decode, Encode};
use core::{borrow::Borrow, marker::PhantomData};
use primitive_types::H256;
use rlp::{DecoderError, Prototype, Rlp, RlpStream};
use trie_db::{
	node::{NibbleSlicePlan, NodeHandlePlan, NodePlan, Value, ValuePlan},
	ChildReference, NodeCodec,
};
use serde::Deserialize;

risc0_zkvm::guest::entry!(main);

// TODO add separate lib with this functionality 

// The storage proof verification code was written using as example https://github.com/ComposableFi/patricia-merkle-trie
// Following that example, whole snippets of Parity Technologies code have been added, like https://github.com/ComposableFi/patricia-merkle-trie/blob/main/src/storage_proof.rs

/// Concrete implementation of a `NodeCodec` with Rlp encoding, generic over the `Hasher`
#[derive(Default, Clone)]
pub struct RlpNodeCodec<H: Hasher> {
	mark: PhantomData<H>,
}

const HASHED_NULL_NODE: [u8; 32] = [
	0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
	0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

// NOTE: what we'd really like here is:
// `impl<H: Hasher> NodeCodec<H> for RlpNodeCodec<H> where H::Out: Decodable`
// but due to the current limitations of Rust const evaluation we can't
// do `const HASHED_NULL_NODE: H::Out = H::Out( … … )`. Perhaps one day soon?
impl<H> NodeCodec for RlpNodeCodec<H>
where
	H: Hasher<Out = H256>,
{
	type Error = DecoderError;
	type HashOut = H::Out;

	fn hashed_null_node() -> H::Out {
		H256(HASHED_NULL_NODE)
	}

	fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
		if data == &HASHED_NULL_NODE {
			// early return if this is == keccak(rlp(null)), aka empty trie root
			// source: https://ethereum.github.io/execution-specs/diffs/frontier_homestead/trie/index.html#empty-trie-root
			return Ok(NodePlan::Empty)
		}

		let r = Rlp::new(data);
		match r.prototype()? {
			// either leaf or extension - decode first item with NibbleSlice::???
			// and use is_leaf return to figure out which.
			// if leaf, second item is a value (is_data())
			// if extension, second item is a node (either SHA3 to be looked up and
			// fed back into this function or inline RLP which can be fed back into this function).
			Prototype::List(2) => {
				let (rlp, offset) = r.at_with_offset(0)?;
				let (data, i) = (rlp.data()?, rlp.payload_info()?);
				match (
					NibbleSlicePlan::new(
						(offset + i.header_len)..(offset + i.header_len + i.value_len),
						if data[0] & 16 == 16 { 1 } else { 2 },
					),
					data[0] & 32 == 32,
				) {
					(slice, true) => Ok(NodePlan::Leaf {
						partial: slice,
						value: {
							let (item, offset) = r.at_with_offset(1)?;
							let i = item.payload_info()?;
							ValuePlan::Inline(
								(offset + i.header_len)..(offset + i.header_len + i.value_len),
							)
						},
					}),
					(slice, false) => Ok(NodePlan::Extension {
						partial: slice,
						child: {
							let (item, offset) = r.at_with_offset(1)?;
							let i = item.payload_info()?;
							NodeHandlePlan::Hash(
								(offset + i.header_len)..(offset + i.header_len + i.value_len),
							)
						},
					}),
				}
			},
			// branch - first 16 are nodes, 17th is a value (or empty).
			Prototype::List(17) => {
				let mut nodes = [
					None, None, None, None, None, None, None, None, None, None, None, None, None,
					None, None, None,
				];

				for index in 0..16 {
					let (item, offset) = r.at_with_offset(index)?;
					let i = item.payload_info()?;
					if item.is_empty() {
						nodes[index] = None;
					} else {
						nodes[index] = Some(NodeHandlePlan::Hash(
							(offset + i.header_len)..(offset + i.header_len + i.value_len),
						));
					}
				}

				Ok(NodePlan::Branch {
					children: nodes,
					value: {
						let (item, offset) = r.at_with_offset(16)?;
						let i = item.payload_info()?;
						if item.is_empty() {
							None
						} else {
							Some(ValuePlan::Inline(
								(offset + i.header_len)..(offset + i.header_len + i.value_len),
							))
						}
					},
				})
			},
			// an empty branch index.
			Prototype::Data(0) => Ok(NodePlan::Empty),
			// something went wrong.
			_ => Err(DecoderError::Custom("Rlp is not valid.")),
		}
	}

	fn is_empty_node(data: &[u8]) -> bool {
		Rlp::new(data).is_empty()
	}

	fn empty_node() -> &'static [u8] {
		&[0x80]
	}

	fn leaf_node(
		partial: impl Iterator<Item = u8>,
		_number_nibble: usize,
		value: Value,
	) -> Vec<u8> {
		let mut stream = RlpStream::new_list(2);
		let partial = partial.collect::<Vec<_>>();
		stream.append(&partial);
		let value = match value {
			Value::Node(bytes) => bytes,
			Value::Inline(bytes) => bytes,
		};
		stream.append(&value);
		stream.out().to_vec()
	}

	fn extension_node(
		partial: impl Iterator<Item = u8>,
		_number_nibble: usize,
		child_ref: ChildReference<Self::HashOut>,
	) -> Vec<u8> {
		let mut stream = RlpStream::new_list(2);
		stream.append(&partial.collect::<Vec<_>>());
		match child_ref {
			ChildReference::Hash(h) => stream.append(&h.as_ref()),
			ChildReference::Inline(inline_data, len) => {
				let bytes = &AsRef::<[u8]>::as_ref(&inline_data)[..len];
				stream.append_raw(bytes, 1)
			},
		};
		stream.out().to_vec()
	}

	fn branch_node(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<Value>,
	) -> Vec<u8> {
		let mut stream = RlpStream::new_list(17);
		for child_ref in children {
			match child_ref.borrow() {
				Some(c) => match c {
					ChildReference::Hash(h) => stream.append(&h.as_ref()),
					ChildReference::Inline(inline_data, len) => {
						let bytes = &inline_data[..*len];
						stream.append_raw(bytes, 1)
					},
				},
				None => stream.append_empty_data(),
			};
		}
		if let Some(value) = value {
			let value = match value {
				Value::Node(bytes) => bytes,
				Value::Inline(bytes) => bytes,
			};
			stream.append(&value);
		} else {
			stream.append_empty_data();
		}
		stream.out().to_vec()
	}

	fn branch_node_nibbled(
		_partial: impl Iterator<Item = u8>,
		_number_nibble: usize,
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		_value: Option<Value>,
	) -> Vec<u8> {
		unimplemented!("Ethereum branch nodes do not have partial key; qed")
	}
}


#[derive(Debug)]
pub struct KeccakHasher;

impl hash_db::Hasher for KeccakHasher {
    type Out = H256;

    type StdHasher = Hash256StdHasher;

    const LENGTH: usize = H256::len_bytes();

    fn hash(x: &[u8]) -> Self::Out {
      let mut hasher = Keccak::v256();
      hasher.update(x);

      let mut result: [u8; 32] = [0u8; 32];
      hasher.finalize(&mut result);

      primitive_types::H256(result)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Encode, Decode)]
pub struct StorageProof {
	trie_nodes: BTreeSet<Vec<u8>>,
}

/// Aliased memory db type
pub type MemoryDB<H> = memory_db::MemoryDB<
	H,
	memory_db::HashKey<H>,
	trie_db::DBValue,
	memory_db::NoopTracker<trie_db::DBValue>,
>;

impl StorageProof {
	/// Constructs a storage proof from a subset of encoded trie nodes in a storage backend.
	pub fn new(trie_nodes: impl IntoIterator<Item = Vec<u8>>) -> Self {
		StorageProof { trie_nodes: BTreeSet::from_iter(trie_nodes) }
	}

  /// Creates a [`MemoryDB`](memory_db::MemoryDB) from `Self`.
	pub fn into_memory_db<H: hash_db::Hasher>(self) -> MemoryDB<H> {
		self.into()
	}

  /// Create an iterator over encoded trie nodes in lexicographical order constructed
	/// from the proof.
	pub fn iter_nodes(self) -> StorageProofNodeIterator {
		StorageProofNodeIterator::new(self)
	}
}

/// An iterator over trie nodes constructed from a storage proof. The nodes are not guaranteed to
/// be traversed in any particular order.
pub struct StorageProofNodeIterator {
	inner: <BTreeSet<Vec<u8>> as IntoIterator>::IntoIter,
}

impl StorageProofNodeIterator {
	fn new(proof: StorageProof) -> Self {
		StorageProofNodeIterator { inner: proof.trie_nodes.into_iter() }
	}
}

impl Iterator for StorageProofNodeIterator {
	type Item = Vec<u8>;

	fn next(&mut self) -> Option<Self::Item> {
		self.inner.next()
	}
}

impl<H: Hasher> From<StorageProof> for MemoryDB<H> {
	fn from(proof: StorageProof) -> Self {
		let mut db = MemoryDB::default();
		proof.iter_nodes().for_each(|n| {
			db.insert(hash_db::EMPTY_PREFIX, &n);
		});
		db
	}
}

/// Trie layout for EIP-1186 state proof nodes.
#[derive(Default, Clone)]
pub struct EIP1186Layout<H>(PhantomData<H>);

impl<H: Hasher<Out = H256>> TrieLayout for EIP1186Layout<H> {
	const USE_EXTENSION: bool = true;
	const ALLOW_EMPTY: bool = false;
	const MAX_INLINE_VALUE: Option<u32> = None;
	type Hash = H;
	type Codec = RlpNodeCodec<H>;
}

#[derive(Debug, Deserialize)]
struct StorageProofInput {
  key: Vec<u8>,
  proof: Vec<Vec<u8>>,
  root: [u8; 32]
}

fn main() {
    // Read data sent from the application contract.
    let mut input_bytes = Vec::<u8>::new();
    env::stdin().read_to_end(&mut input_bytes).unwrap();

    let input = ethabi::decode(&[ethabi::ParamType::Uint(256), ethabi::ParamType::String], &input_bytes).unwrap();
    let id: U256 = input[0].clone().into_uint().unwrap();
    let extracted_string = match &input[1] {
      ethabi::Token::String(value) => value.clone(),
      _ => panic!("Expected bytes"),
    };  

    // TODO add error handling
	#[allow(non_snake_case)]
    let storageProof: StorageProofInput = serde_json::from_str(&extracted_string).unwrap();

    let key = KeccakHasher::hash(&storageProof.key);
    let root = H256(storageProof.root);
    let db = StorageProof::new(storageProof.proof).into_memory_db::<KeccakHasher>();
    let trie = TrieDBBuilder::<EIP1186Layout<KeccakHasher>>::new(&db, &root).build();
    let res = trie.get(&key.0).unwrap().unwrap();

    // Commit the journal that will be received by the application contract.
    // Encoded types should match the args expected by the application callback.
    env::commit_slice(&ethabi::encode(&[Token::Uint(id), Token::Uint(res[0].into())]));
}

// TODO rename file and image