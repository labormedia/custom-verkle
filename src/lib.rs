use std::collections::{
    HashMap,
    BTreeMap,
};
use sha2::{Digest, Sha256};

/// A basic Verkle Tree Node
#[derive(Debug, Clone)]
enum VerkleNode {
    InnerNode { children: BTreeMap<u8, Box<VerkleNode>>, commitment: Vec<u8>, value: Vec<u8>},
    LeafNode { key: Vec<u8>, value: Vec<u8> },
}

/// A simplified Verkle Tree implementation
#[derive(Debug)]
pub struct VerkleTree {
    root: VerkleNode,
    stored_commitment: Vec<u8>,
}

impl VerkleTree {
    /// Creates a new empty Verkle Tree
    pub fn new() -> Self {
        VerkleTree {
            root: VerkleNode::InnerNode {
                children: BTreeMap::new(),
                commitment: vec![],
                value: vec![]
            },
            stored_commitment: vec![],
        }
    }

    /// Inserts a key-value pair into the Verkle tree
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let mut current_node = &mut self.root;
        let mut path = Vec::new();
        
        for byte in key {
            path.push(*byte);
            match current_node {
                VerkleNode::InnerNode { children, .. } => {
                    current_node = children
                        .entry(*byte)
                        .or_insert_with(|| Box::new(VerkleNode::InnerNode { 
                            children: BTreeMap::new(), 
                            commitment: vec![],
                            value: vec![]
                        }));
                },
                VerkleNode::LeafNode { key: existing_key, value: existing_value, .. } => {
                    if existing_key == key {
                        // If the key already exists, update the value
                        *current_node = VerkleNode::LeafNode {
                            key: existing_key.clone(),
                            value: value.to_vec(),
                        };
                        return;
                    } else {
                        // Handle key-prefix collision
                        let mut new_inner_node = VerkleNode::InnerNode {
                            children: BTreeMap::new(),
                            commitment: vec![],
                            value: existing_value.clone()
                        };

                        // Reinsert the existing leaf node into the new inner node
                        if let VerkleNode::InnerNode { ref mut children, .. } = new_inner_node {
                            // let existing_byte = existing_key[path.len() - 1];
                            // children.insert(existing_byte, Box::new(current_node.clone()));
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
                                }));
                        }
                    }
                },
                _ => panic!("Trying to insert into a leaf node!"), // It's ok to panic if the algorithm is not able to insert a correctly-typed key and value
            }
        }
        
        *current_node = VerkleNode::LeafNode {
            key: key.to_vec(),
            value: value.to_vec(),
        };

        // Update the stored commitment after insertion
        self.stored_commitment = self.compute_commitment();
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
                }
                _ => return None,
            }
        }
        
        match current_node {
            VerkleNode::LeafNode { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Computes a simple commitment (mocked with SHA-256 hash for now)
    pub fn compute_commitment(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        self.compute_commitment_recursive(&self.root, &mut hasher);
        hasher.finalize().to_vec()
    }

    fn compute_commitment_recursive(&self, node: &VerkleNode, hasher: &mut Sha256) {
        match node {
            VerkleNode::InnerNode { children, .. } => {
                for (k, child) in children {
                    println!("to hash inner {}", k);
                    hasher.update(&[*k]);
                    self.compute_commitment_recursive(child, hasher);
                }
            }
            VerkleNode::LeafNode { key, value } => {
                println!("to hash leaf {:?} {:?}", key, value);
                hasher.update(key);
                hasher.update(value);
            }
        }
    }

    /// Verifies if the stored commitment matches the computed commitment
    pub fn verify_commitment(&self) -> bool {
        let computed_commitment = self.compute_commitment();
        self.stored_commitment == computed_commitment
    }

    /// Generates a proof for a given key
    pub fn generate_proof(&self, key: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>, Vec<u8>)> {
        let mut current_node = &self.root;
        let mut proof = Vec::new();

        for byte in key {
            match current_node {
                VerkleNode::InnerNode { children, commitment, value } => { // TODO: value would need to be included in the hash calculation
                    proof.push(commitment.clone());
                    if let Some(child) = children.get(byte) {
                        current_node = child;
                    } else {
                        return None;
                    }
                }
                _ => return None,
            }
        }

        if let VerkleNode::LeafNode { key, value } = current_node {
            Some((key.clone(), proof, self.stored_commitment.clone()))
        } else if let VerkleNode::InnerNode { children, commitment, value } = current_node {
            Some((key.to_vec(), proof, self.stored_commitment.clone()))
        } else {
            None
        }
    }
    

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
    
    let (mut key, proof, root_commitment) = tree.generate_proof(b"421").unwrap();
    assert_eq!(tree.generate_proof(b"421a"), None );
    let (mut key, proof, root_commitment) = tree.generate_proof(b"4212").unwrap();
}

#[test]
fn three_key_lookup() {
    let mut tree = VerkleTree::new();
    
    // Insert values
    tree.insert(b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc", b"squirrel");
    tree.insert(b"284afea09032d2daf30f98cfc36e4b2205cbf6e4edb69994c7261e6287b60609", b"dog");
    tree.insert(b"284acat", b"cat");

    let (mut key, proof, root_commitment) = tree.generate_proof(b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc").unwrap();
    assert_eq!(proof, [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]);

    let (key, proof, root_commitment) = tree.generate_proof(b"284afea09032d2daf30f98cfc36e4b2205cbf6e4edb69994c7261e6287b60609").unwrap();
    assert_eq!(proof, [[], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]);
    
    let (key, proof, root_commitment) = tree.generate_proof(b"284acat").unwrap();
    assert_eq!(proof, [[], [], [], [], [], [], []]);
    
    let unknown_key_proof = tree.generate_proof(b"284acats");
    assert_eq!(unknown_key_proof, None);
}