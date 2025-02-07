use std::collections::HashMap;
use sha2::{Digest, Sha256};

/// A basic Verkle Tree Node
#[derive(Debug, Clone)]
enum VerkleNode {
    InnerNode { children: HashMap<u8, Box<VerkleNode>>, commitment: Vec<u8> },
    LeafNode { key: Vec<u8>, value: Vec<u8> },
}

/// A simplified Verkle Tree implementation
#[derive(Debug)]
pub struct VerkleTree {
    root: VerkleNode,
}

impl VerkleTree {
    /// Creates a new empty Verkle Tree
    pub fn new() -> Self {
        VerkleTree {
            root: VerkleNode::InnerNode {
                children: HashMap::new(),
                commitment: vec![],
            },
        }
    }

    /// Inserts a key-value pair into the Verkle tree
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let mut current_node = &mut self.root;
        
        for byte in key {
            match current_node {
                VerkleNode::InnerNode { children, .. } => {
                    current_node = children
                        .entry(*byte)
                        .or_insert_with(|| Box::new(VerkleNode::InnerNode { 
                            children: HashMap::new(), 
                            commitment: vec![] 
                        }));
                }
                _ => panic!("Trying to insert into a leaf node!"),
            }
        }
        
        *current_node = VerkleNode::LeafNode {
            key: key.to_vec(),
            value: value.to_vec(),
        };
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
                    hasher.update(&[*k]);
                    self.compute_commitment_recursive(child, hasher);
                }
            }
            VerkleNode::LeafNode { key, value } => {
                hasher.update(key);
                hasher.update(value);
            }
        }
    }
}
