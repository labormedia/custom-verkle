use std::collections::{
    HashMap,
    BTreeMap,
};
use sha2::{Digest, Sha512};
pub use curve25519_dalek::scalar::Scalar;
pub use curve25519_dalek::ristretto::RistrettoPoint;
pub use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
pub use curve25519_dalek::traits::Identity;
use rand::{
    CryptoRng,
    rngs::OsRng,
};
pub mod traits;

#[derive(Clone, Debug, PartialEq)]
pub struct Commitment(RistrettoPoint, Scalar);

/// A basic Verkle Tree Node
#[derive(Debug, Clone, PartialEq)]
pub enum VerkleNode {
    InnerNode { children: BTreeMap<u8, Box<VerkleNode>>, commitment: Commitment, value: Vec<u8>},
    LeafNode { key: Vec<u8>, value: Vec<u8>, commitment: Commitment },
}

/// A simplified Verkle Tree implementation
#[derive(Debug, Clone)]
pub struct VerkleTree {
    root: VerkleNode,
    stored_commitment: Commitment,
    aggregated_blinding_factors: Scalar,
    transcript_point: RistrettoPoint,
}

impl Commitment {
    pub fn tuple(&self) -> (RistrettoPoint, Scalar) {
        (self.0, self.1)
    }
    pub fn get_ristretto(&self) -> RistrettoPoint {
        self.0
    }
}

impl VerkleTree {
    /// Creates a new empty Verkle Tree with VerkleNode::InnerNode. This is important because VerkleNode::LeafNode are terminating logic.
    pub fn new() -> Self {
        let initial_key = vec![];
        let initial_value = vec![];
        let (commitment, blinding_factor) = Self::pedersen_commitment(&initial_key, &initial_value).tuple();
        let transcript = b"transcript";
        VerkleTree {
            root: VerkleNode::InnerNode {
                children: BTreeMap::new(),
                commitment: (commitment, blinding_factor).into(),
                value: initial_value.clone()
            },
            stored_commitment: (commitment, Scalar::hash_from_bytes::<Sha512>(&initial_value)).into(),
            aggregated_blinding_factors: blinding_factor,
            transcript_point: RistrettoPoint::hash_from_bytes::<Sha512>(transcript),
        }
    }

    /// Inserts a key-value pair into the Verkle tree
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let mut current_node = &mut self.root;
        let mut path = Vec::new();
        let commitment = Self::pedersen_commitment(key, value);

        for (position, byte) in key.into_iter().enumerate() {
            path.push(*byte);                     
            match current_node {
                VerkleNode::InnerNode { children, value: existing_value, commitment: existing_commitment } => {
                    #[cfg(debug_assertions)]
                    println!("InnerNode value {:?} for byte {} path {}", value, byte, String::from_utf8_lossy(&path));   
                    if path == key {
                        #[cfg(debug_assertions)]
                        println!("path == key {} {:?} byte {}", path == key, key, byte);
                        current_node = children
                            .entry(*byte)
                            .or_insert_with(|| Box::new(
                                VerkleNode::LeafNode {
                                    key: key.to_vec(),
                                    value: value.to_vec(),
                                    commitment: commitment.clone(),
                                }
                            ));
                    } else {
                        #[cfg(debug_assertions)]
                        println!("Retrieves or insert new InnerNode with children length {} path {}", children.len(), String::from_utf8_lossy(&path));
                        current_node = children
                            .entry(*byte)
                            .or_insert_with(|| Box::new(
                                VerkleNode::InnerNode { 
                                    children: BTreeMap::new(), 
                                    commitment: existing_commitment.clone(),
                                    value: vec![]
                                }
                            ));
                    };
                }
                VerkleNode::LeafNode { key: existing_key, value: existing_value, .. } => {
                    if existing_key == key {
                        // If the key already exists, update the value
                        *current_node = VerkleNode::LeafNode {
                            key: key.to_vec(),
                            value: value.to_vec(),
                            commitment,
                        };
                        
                        return;
                    } else {
                        // Handle key-prefix collision
                        let mut new_inner_node = VerkleNode::InnerNode {
                            children: BTreeMap::new(),
                            commitment: Self::pedersen_commitment(&path, existing_value),
                            value: existing_value.to_vec()
                        };

                        // Reinsert the existing leaf node into the new inner node
                        if let VerkleNode::InnerNode { ref mut children, .. } = new_inner_node {
                            let existing_byte = key[position];
                            #[cfg(debug_assertions)]
                            println!("Inserting child with key {} position {} to new InnerNode path {}", String::from_utf8_lossy(existing_key), position, String::from_utf8_lossy(&path));
                            #[cfg(debug_assertions)]
                            println!("Existing byte {} {}", existing_byte, String::from_utf8_lossy(existing_value));
                            //children.insert(existing_byte, Box::new(current_node.clone()));
                        }

                        // Replace the current node with the new inner node
                        *current_node = new_inner_node;
                        
                        // Continue inserting the new key-value pair
                        if let VerkleNode::InnerNode { ref mut children, .. } = current_node {
                            #[cfg(debug_assertions)]
                            println!("Looking for byte {}", byte);
                            current_node = children
                                .entry(*byte)
                                .or_insert_with(|| Box::new(VerkleNode::LeafNode {
                                    key: key.to_vec(),
                                    value: value.to_vec(),
                                    commitment: commitment.clone(),
                                }));
                        }
                        
                    }
                }
            }
        }

        // Recompute root commitment up to the root
        let (agreggated_commitment, aggregated_blinding_factors) = Self::compute_commitment_recursive(&mut self.root);
        self.stored_commitment = agreggated_commitment.into();
        self.aggregated_blinding_factors = aggregated_blinding_factors;
    }
    
    /// Computes a Pedersen commitment for a key-value pair
    fn pedersen_commitment(key: &[u8], value: &[u8]) -> Commitment {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let value_scalar = Scalar::hash_from_bytes::<Sha512>(value);
        (r * RISTRETTO_BASEPOINT_POINT + value_scalar * RISTRETTO_BASEPOINT_POINT, r).into()
    }
    
    /// Commits to a key, value, blinding_factor combination.
    pub fn commit(key: &[u8], value:&[u8], blinding_factor: Scalar) -> RistrettoPoint {
        let value_scalar = Scalar::hash_from_bytes::<Sha512>(value);
        blinding_factor * RISTRETTO_BASEPOINT_POINT + value_scalar * RISTRETTO_BASEPOINT_POINT
    }
    
    /// Commits to a hashed value and blinding_factor combination.
    pub fn commit_hashed_value(hash_value: &Scalar, blinding_factor: &Scalar) -> RistrettoPoint {
        blinding_factor * RISTRETTO_BASEPOINT_POINT + hash_value * RISTRETTO_BASEPOINT_POINT
    }
    
    /// Verifies a given Pedersen commitment (revealing the secret)
    pub fn verify_pedersen_commitment(key: &[u8], value: &[u8], commitment: &Commitment) -> bool {
        let (ristretto, r) = commitment.tuple();
        let value_scalar = Scalar::hash_from_bytes::<Sha512>(value);
        r * RISTRETTO_BASEPOINT_POINT + value_scalar * RISTRETTO_BASEPOINT_POINT == ristretto
    }

    /// Retrieves a value given a key
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let mut current_node = &self.root;
        
        for byte in key {
            match current_node {
                VerkleNode::InnerNode { children, .. } => {
                    if let Some(child) = children.get(byte) {
                        current_node = child;
                    } else {
                        return None;
                    }
                },
                _ => return None,
            }
        }
        
        match current_node {
            VerkleNode::LeafNode { value, .. } => Some(value),
            VerkleNode::InnerNode { children, commitment, value } => Some(value),
        }
    }

    /// Computes the root commitment
    pub fn compute_commitment(&mut self) -> Commitment {
        Self::compute_commitment_recursive(&mut self.root).0.into()
    }
    
    /// hash_from_bytes wrapped helper
    pub fn hash_from_bytes(value: &[u8]) -> Scalar {
        Scalar::hash_from_bytes::<Sha512>(value)
    }

    /// Computes root commitment
    /// returns the equivalent to the sum of all node commitments and values aggregated to they hash in bytes
    /// in the form (RistrettoPoint, Scalar), which can be transformed to Commitment type conveniently
    pub fn compute_commitment_recursive(node: &mut VerkleNode) -> ((RistrettoPoint, Scalar), Scalar) {
        let mut combined_commitment: RistrettoPoint = RistrettoPoint::identity();
        let mut combined_values: Scalar = Scalar::ZERO;
        let mut aggregated_blinded_factor: Scalar = Scalar::ZERO;
        match node {
            VerkleNode::InnerNode { children, commitment, value } => {
                #[cfg(debug_assertions)]
                println!("Children length {} and commitment_length", children.len());
                let to_sum = commitment.0;
                #[cfg(debug_assertions)]
                println!("Compressed {:?}", to_sum.compress());
                combined_commitment = to_sum;
                combined_values += Self::hash_from_bytes(&value);
                aggregated_blinded_factor += commitment.1;
                for child in children.values_mut() {
                    let ((to_sum, values), blinded_factors) = Self::compute_commitment_recursive(child); // TODO: Add blinded logic
                    #[cfg(debug_assertions)]
                    println!("Compressed {:?}", to_sum.compress());
                    combined_commitment += to_sum;
                    combined_values += values;
                    aggregated_blinded_factor += blinded_factors;
                }
                ((combined_commitment, combined_values), aggregated_blinded_factor)
            }
            VerkleNode::LeafNode { commitment, value, .. } => {
                #[cfg(debug_assertions)]
                println!("Ending on LeafNode for compute_commitment_recursive blinding_factor {:?}", commitment.1);
                let single_commitment = commitment.0;
                let single_value = Self::hash_from_bytes(&value);
                #[cfg(debug_assertions)]
                println!("Compressed {:?}", single_commitment.compress());
                ((single_commitment, single_value), commitment.1)
            },
        }
    }
    
    // Traverses and counts the tree nodes.
    pub fn count(&self) -> usize {
        Self::count_from(&self.root, &mut 0_usize)
    }
    
    // Recursive count from an origin
    fn count_from(node: &VerkleNode, count: &mut usize) -> usize {
        match node {
            VerkleNode::InnerNode { children, .. } => {
                *count += 1;
                for (branch, node) in children.iter() {
                    #[cfg(debug_assertions)]
                    println!("Branch {}", branch);
                    Self::count_from(node, count);
                }
                *count
            }
            VerkleNode::LeafNode { key, .. } => {
                *count += 1;
                #[cfg(debug_assertions)]
                println!("Leaf {}", String::from_utf8_lossy(key));
                *count
            },
        }
    }

    /// Verifies if the stored commitment matches the computed commitment
    pub fn verify_root(&mut self) -> bool {
        let blinding_factor = self.aggregated_blinding_factors.clone();
        let (ristretto, hashed_values) = Self::compute_commitment_recursive(&mut self.root).0.into();
        ristretto == blinding_factor * RISTRETTO_BASEPOINT_POINT + hashed_values * RISTRETTO_BASEPOINT_POINT
        && self.stored_commitment == Self::compute_commitment_recursive(&mut self.root).0.into()
    }
    
    pub fn verify_desaggregated_commitment(&self, ristretto: RistrettoPoint, hash_value: Scalar, blinded_factor: Scalar) -> bool {
        let desaggregated_blinded_factor = self.aggregated_blinding_factors - blinded_factor;
        let (commited_proof, commited_values) = ( self.stored_commitment.clone() - (ristretto, hash_value).into() ).tuple();
        commited_proof == Self::commit_hashed_value(&commited_values, &desaggregated_blinded_factor)
    }

    /// Generates a proof for a given key
    pub fn generate_proof(&self, key: &[u8]) -> Option<((Vec<u8>, Vec<u8>), Vec<Commitment>, Commitment)> {
        let mut current_node = &self.root;
        let mut proof = Vec::new();
        
        for (pos, byte) in key.into_iter().enumerate() {
            match current_node {
                VerkleNode::InnerNode { children, commitment, value } => {
                    #[cfg(debug_assertions)]
                    println!("touch {} {}", children.len(), byte);
                    if let Some(child) = children.get(byte) {
                        #[cfg(debug_assertions)]
                        println!("Inserting commitment when generating proof for key {} byte {} position {}", String::from_utf8_lossy(key), byte, pos);
                        proof.push(commitment.clone()) ;
                        current_node = child;
                    } else {
                        return None;
                        // Key not found
                    }
                }
                VerkleNode::LeafNode { key: existing_key, commitment, value:existing_value } => {
                    #[cfg(debug_assertions)]
                    println!("LeafNode key {:?} value {:?} pos {}", existing_key, existing_value, pos);
                    if existing_key == key {
                        return Some(((existing_key.clone(), existing_value.clone()), proof, commitment.clone()));
                    } else {
                        return None; // Key not found
                    }
                }
            }
        }
        match current_node {
            VerkleNode::LeafNode { key: existing_key, commitment, value: existing_value } => {
                #[cfg(debug_assertions)]
                println!("LeafNode happens ?");
                Some(((existing_key.clone(), existing_value.clone()), proof, commitment.clone()) )
            },
            VerkleNode::InnerNode { commitment, value: existing_value, children } => {
                #[cfg(debug_assertions)]
                println!("current_node == &self.root ? {}", current_node == &self.root);
                #[cfg(debug_assertions)]
                println!("Children length {}", children.len());
                Some(((key.to_vec(), existing_value.clone()), proof, commitment.clone() ))
            },
        }
    }
    

}

#[test]
fn empty_tree() {
    let mut tree = VerkleTree::new();
    assert!(tree.verify_root())
}

#[test]
fn three_node_tree_simple() {
    let mut tree = VerkleTree::new();
    assert_eq!(tree.count(), 1);
    tree.insert(b"a", b"a");
    assert_eq!(tree.count(), 2);
    tree.insert(b"bb", b"b");
    assert_eq!(tree.count(), 4);
    tree.insert(b"ccc", b"c");
    assert_eq!(tree.count(), 7);
    tree.insert(b"ccd", b"d");
    assert_eq!(tree.count(), 8);
}

#[test]
fn one_node_tree() {
    let mut tree = VerkleTree::new();
    let (initial_key, initial_value): (Vec<u8>, Vec<u8>) = (vec![], vec![]);
    let (ristretto, blinding_factor) = VerkleTree::pedersen_commitment(&initial_key, &initial_value).tuple();
    let ((key, value), proof, initial_commitment) = tree.generate_proof(&initial_key).unwrap();    
    let (compare_commitment, blinding_factor_aggregate) = proof.into_iter().sum::<Commitment>().tuple();
    assert_eq!(blinding_factor_aggregate, Scalar::from(0_u64));
    let (initial_root, _) = tree.compute_commitment().tuple();
    assert_eq!(initial_root, initial_commitment.0);
    tree.insert(b"420000", b"cat");
    let (root_after_insertion, _) = tree.compute_commitment().tuple();
    assert_ne!(initial_root, root_after_insertion);
    
    let ((key, value), proof, posterior_commitment) = tree.generate_proof(b"420000").unwrap();
    assert_eq!(proof.len(), 6_usize); // The cardinality of nodes added is given by the characters to include as children from the root, in this case 6
    assert_eq!(proof[0].0, initial_root);
    
    let blinding_factor = posterior_commitment.1;
    
    let compare_commitment: RistrettoPoint = proof.into_iter().map( |x| {
        x.0
    }).sum();
    tree.verify_root();
    assert_eq!(root_after_insertion, tree.compute_commitment().tuple().0);
    assert_eq!(root_after_insertion, compare_commitment + posterior_commitment.0);
    assert_eq!(root_after_insertion - posterior_commitment.0, compare_commitment);
    assert_eq!(root_after_insertion - compare_commitment, posterior_commitment.0);
    // The new root minus the sum of proofs is equal to the pedersen commit with the blinding_factor associated
    // This is only the case only for one leaf node inserted to the tree
    assert_eq!(root_after_insertion - compare_commitment, VerkleTree::commit(b"420000", b"cat", blinding_factor));
}

#[test]
fn short_keys() {
    let mut tree = VerkleTree::new();
    #[cfg(debug_assertions)]
    println!("First insert, 420 cat"); 
    tree.insert(b"420", b"cat");
    #[cfg(debug_assertions)]
    println!("Second insert, 421 dog");
    tree.insert(b"421", b"dog");
    #[cfg(debug_assertions)]
    println!("Third insert, 4212 squirrel");
    tree.insert(b"4212", b"squirrel");
    #[cfg(debug_assertions)]
    println!("Inserting 4212 ended");
    
    assert_eq!(tree.get(b"421").unwrap(), b"dog");
    #[cfg(debug_assertions)]
    println!("Getting 421 ended");
    assert_eq!(tree.get(b"4212").unwrap(), b"squirrel");
    assert_eq!(tree.get(b"4213"), None);
    assert_eq!(tree.generate_proof(b"421a"), None );
    
    let ((key, value), proof, commitment) = tree.generate_proof(b"421").unwrap();
    assert_eq!(value, b"dog");
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &commitment));
    let ((key, value), proof, commitment) = tree.generate_proof(b"4212").unwrap();
    assert_eq!(value, b"squirrel");
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &commitment));
}

#[test]
fn three_key_lookup() {
    let mut tree = VerkleTree::new();
    
    let (root, _) = tree.compute_commitment().tuple();
    
    // Insert values
    let key1 = b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc";
    let key2 = b"284afea09032d2daf30f98cfc36e4b2205cbf6e4edb69994c7261e6287b60609";
    let key3 = b"284acat";
    tree.insert(key1, b"squirrel");
    tree.insert(key2, b"dog");
    tree.insert(key3, b"cat");

    let total_length = key1.len() + key2.len() + key3.len();
    let nodes_overlapping = b"284a"; // key2's initial overlapping with key3
    
    assert_eq!(total_length + 1 - nodes_overlapping.len(), tree.count());

    let ((key, value), proof, commitment) = tree.generate_proof(key1).unwrap();
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &commitment));

    let ((key, value), proof, commitment) = tree.generate_proof(key2).unwrap();
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &commitment));
    
    let unknown_key_proof = tree.get(b"284acats");
    assert_eq!(unknown_key_proof, None);
    
    let unknown_key_proof = tree.generate_proof(b"284acats");
    assert_eq!(unknown_key_proof, None);
    
    let ((key, value), proof, node_commitment) = tree.generate_proof(key1).unwrap();
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &node_commitment));
    
    // Verifies desaggregated commitment (from root)
    assert!( tree.verify_desaggregated_commitment(node_commitment.0, VerkleTree::hash_from_bytes(&value), node_commitment.1) );
    
    assert_eq!(b"squirrel", tree.get(key1).unwrap());
    assert_eq!(b"dog", tree.get(key2).unwrap());
    assert_eq!(b"cat", tree.get(key3).unwrap());
    
    assert_eq!(key.len(), proof.len());
    assert_eq!(proof[0].0, root);
    assert_ne!(proof.last().unwrap(), &node_commitment);
    
    assert!(tree.verify_root());
    
}

#[test]
fn desaggregate_any_value() {
    let mut tree = VerkleTree::new();
    
    let first = (b"now", b"movies");
    let second = (b"past", b"golf");
    let third = (b"future", b"tennis");
    let fourth = (b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc", b"284acat");
    
    tree.insert(first.0, first.1);
    
    let mut rng = OsRng;
    let any_key = b"64d9f1cf9079ebe514609550e3fd51e7a75 any key";
    let any_value = b"any value 64d9f1cf9079ebe514609550e3fd51e7a75";
    let hashed_value = Scalar::hash_from_bytes::<Sha512>(any_value);
    let r = Scalar::random(&mut rng);
    let commit = VerkleTree::commit_hashed_value(&hashed_value, &r);
    
    // Verifies desaggregation of "any value"
    assert!( tree.verify_desaggregated_commitment(commit, hashed_value, r) );
}

#[should_panic]
#[test]
fn failed_desaggregate_any_value() {
    let mut tree = VerkleTree::new();
    
    let first = (b"now", b"movies");
    let second = (b"past", b"golf");
    let third = (b"future", b"tennis");
    let fourth = (b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc", b"284acat");
    
    tree.insert(first.0, first.1);
    
    let mut rng = OsRng;
    let any_key = b"64d9f1cf9079ebe514609550e3fd51e7a75 any key";
    let any_value = b"any value 64d9f1cf9079ebe514609550e3fd51e7a75";
    let hashed_value = Scalar::hash_from_bytes::<Sha512>(any_value);
    let r = Scalar::random(&mut rng);
    let commit = VerkleTree::commit_hashed_value(&hashed_value, &r);
    let another_hashed_value = Scalar::hash_from_bytes::<Sha512>(b"distinct");
    
    // Verifies desaggregation of "any value"
    assert!( tree.verify_desaggregated_commitment(commit, another_hashed_value, r) );
}
    
    