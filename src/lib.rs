use std::collections::{
    HashMap,
    BTreeMap,
};
use sha2::{Digest, Sha512};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand::{
    CryptoRng,
    rngs::OsRng,
};

/// A basic Verkle Tree Node
#[derive(Debug, Clone, PartialEq)]
pub enum VerkleNode {
    InnerNode { children: BTreeMap<u8, Box<VerkleNode>>, commitments: Vec<(RistrettoPoint, Scalar)>, value: Vec<u8>},
    LeafNode { key: Vec<u8>, value: Vec<u8>, commitment: (RistrettoPoint, Scalar) },
}

/// A simplified Verkle Tree implementation
#[derive(Debug, Clone)]
pub struct VerkleTree {
    root: VerkleNode,
    stored_commitment: RistrettoPoint,
}

impl VerkleTree {
    /// Creates a new empty Verkle Tree with VerkleNode::InnerNode. This is important because VerkleNode::LeafNode are terminating logic.
    pub fn new() -> Self {
        let initial_key = vec![];
        let initial_value = vec![];
        let (commitment, blinding_factor) = Self::pedersen_commitment(&initial_key, &initial_value);
        VerkleTree {
            root: VerkleNode::InnerNode {
                children: BTreeMap::new(),
                commitments: vec![(commitment, blinding_factor)],
                value: initial_value
            },
            stored_commitment: commitment,
        }
    }

    /// Inserts a key-value pair into the Verkle tree
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let mut current_node = &mut self.root;
        let mut path = Vec::new();

        for (position, byte) in key.into_iter().enumerate() {
            path.push(*byte);
            match current_node {
                VerkleNode::InnerNode { children, value: existing_value, commitments } => {
                    let commitment = Self::pedersen_commitment(&path, value);
                    current_node = children
                        .entry(*byte)
                        .or_insert_with(|| Box::new(VerkleNode::InnerNode { 
                            children: BTreeMap::new(), 
                            commitments: vec![commitment],
                            value: value.to_vec(),
                        }));
                    commitments.push(commitment);
                }
                VerkleNode::LeafNode { key: existing_key, value: existing_value, .. } => {
                    if existing_key == key {
                        // If the key already exists, update the value
                        *current_node = VerkleNode::LeafNode {
                            key: key.to_vec(),
                            value: value.to_vec(),
                            commitment: Self::pedersen_commitment(existing_key, existing_value),
                        };
                        return;
                    } else {
                        // Handle key-prefix collision
                        let mut new_inner_node = VerkleNode::InnerNode {
                            children: BTreeMap::new(),
                            commitments: vec![Self::pedersen_commitment(key, existing_value)],
                            value: existing_value.to_vec()
                        };

                        // Reinsert the existing leaf node into the new inner node
                        if let VerkleNode::InnerNode { ref mut children, .. } = new_inner_node {
                            let existing_byte = key[position];
                            children.insert(existing_byte, Box::new(current_node.clone()));
                        }

                        // Replace the current node with the new inner node
                        *current_node = new_inner_node;
                        
                        // Continue inserting the new key-value pair
                        if let VerkleNode::InnerNode { ref mut children, .. } = current_node {
                            current_node = children
                                .entry(*byte)
                                .or_insert_with(|| Box::new(VerkleNode::LeafNode {
                                    key: key.to_vec(),
                                    value: value.to_vec(),
                                    commitment: Self::pedersen_commitment(key, value),
                                }));
                        }
                    }
                }
            }
        }
        
        *current_node = VerkleNode::LeafNode {
            key: key.to_vec(),
            value: value.to_vec(),
            commitment: Self::pedersen_commitment(key, value),
        };

        // Recompute commitments up to the root
        self.stored_commitment = Self::compute_commitment_recursive(&mut self.root);
    }
    
    /// Computes a Pedersen commitment for a key-value pair
    fn pedersen_commitment(key: &[u8], value: &[u8]) -> (RistrettoPoint, Scalar) {
        let mut rng = OsRng;
        let r = Scalar::random(&mut rng);
        let value_scalar = Scalar::hash_from_bytes::<Sha512>(value);
        (r * RISTRETTO_BASEPOINT_POINT + value_scalar * RISTRETTO_BASEPOINT_POINT, r)
    }
    
    /// Commits to a key, value, blinding_factor combination.
    pub fn commit(key: &[u8], value:&[u8], blinding_factor: Scalar) -> RistrettoPoint {
        let value_scalar = Scalar::hash_from_bytes::<Sha512>(value);
        blinding_factor * RISTRETTO_BASEPOINT_POINT + value_scalar * RISTRETTO_BASEPOINT_POINT
    }
    
    /// Verifies a given Pedersen commitment (revealing the secret)
    pub fn verify_pedersen_commitment(key: &[u8], value: &[u8], commitment: (RistrettoPoint, Scalar)) -> bool {
        let r = commitment.1;
        let ristretto = commitment.0;
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
            VerkleNode::InnerNode { children, commitments, value } => Some(value),
            _ => unreachable!(),
        }
    }

    /// Computes a simple commitment (mocked with SHA-256 hash for now)
    
    pub fn compute_commitment(&mut self) -> RistrettoPoint {
        Self::compute_commitment_recursive(&mut self.root)
    }
    

    // Computes commitment
    pub fn compute_commitment_recursive(node: &mut VerkleNode) -> RistrettoPoint {
        match node {
            VerkleNode::InnerNode { children, commitments, value } => {
                let mut combined_commitment: RistrettoPoint = commitments.iter().map( |x| x.0 ).sum();
                for child in children.values_mut() {
                    combined_commitment += Self::compute_commitment_recursive(child);
                }
                combined_commitment
            }
            VerkleNode::LeafNode { commitment, .. } => commitment.0,
        }
    }

    /// Verifies if the stored commitment matches the computed commitment
    pub fn verify_root(&mut self) -> bool {
        let computed_commitment = self.compute_commitment();
        self.stored_commitment == computed_commitment
    }

    /// Generates a proof for a given key
    pub fn generate_proof(&self, key: &[u8]) -> Option<((Vec<u8>, Vec<u8>), Vec<Vec<(RistrettoPoint, Scalar)>>, (RistrettoPoint, Scalar))> {
        let mut current_node = &self.root;
        let mut proof = Vec::new();
        
        for byte in key {
            match current_node {
                VerkleNode::InnerNode { children, commitments, value } => {
                    if &self.root != current_node { proof.push(commitments.clone()) };
                    if let Some(child) = children.get(byte) {
                        current_node = child;
                    } else {
                        return None; // Key not found
                    }
                }
                VerkleNode::LeafNode { key: existing_key, commitment, value:existing_value } => {
                    if existing_key == key {
                        return Some(((existing_key.clone(), existing_value.clone()), proof, *commitment));
                    } else {
                        return None; // Key not found
                    }
                }
            }
        }
        match current_node {
            VerkleNode::LeafNode { key: existing_key, commitment, value: existing_value } => {
                println!("LeafNode");
                Some(((existing_key.clone(), existing_value.clone()), proof, *commitment))
            },
            VerkleNode::InnerNode { commitments, value: existing_value, .. } => {
                Some(((key.to_vec(), existing_value.clone()), proof, commitments[0]))
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
fn short_keys() {
    let mut tree = VerkleTree::new();
    println!("First insert, 420 cat"); 
    tree.insert(b"420", b"cat");
    println!("Second insert, 421 dog");
    tree.insert(b"421", b"dog");
    println!("Third insert, 4212 squirrel");
    tree.insert(b"4212", b"squirrel");
    
    assert_eq!(tree.get(b"421").unwrap(), b"dog");
    assert_eq!(tree.get(b"4212").unwrap(), b"squirrel");
    assert_eq!(tree.get(b"4213"), None);
    assert_eq!(tree.generate_proof(b"421a"), None );
    
    let ((key, value), proof, commitment) = tree.generate_proof(b"421").unwrap();
    assert_eq!(value, b"dog");
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, commitment));
    let ((key, value), proof, commitment) = tree.generate_proof(b"4212").unwrap();
    assert_eq!(value, b"squirrel");
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, commitment));
}

#[test]
fn three_key_lookup() {
    let mut tree = VerkleTree::new();
    
    // Insert values
    tree.insert(b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc", b"squirrel");
    tree.insert(b"284afea09032d2daf30f98cfc36e4b2205cbf6e4edb69994c7261e6287b60609", b"dog");
    tree.insert(b"284acat", b"cat");

    let ((key, value), proof, commitment) = tree.generate_proof(b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc").unwrap();
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, commitment));

    let ((key, value), proof, commitment) = tree.generate_proof(b"284afea09032d2daf30f98cfc36e4b2205cbf6e4edb69994c7261e6287b60609").unwrap();
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, commitment));
    
    let ((key, value), proof, commitment) = tree.generate_proof(b"284acat").unwrap();
    assert!(VerkleTree::verify_pedersen_commitment(&key, &value, commitment));
    
    let unknown_key_proof = tree.get(b"284acats");
    assert_eq!(unknown_key_proof, None);
    
    let unknown_key_proof = tree.generate_proof(b"284acats");
    assert_eq!(unknown_key_proof, None);
    
    //assert_eq!(aggregated_proof, tree.compute_commitment() - root_commitment.0);
}