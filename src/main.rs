use custom_verkle::VerkleTree;

fn main() {
    let mut tree = VerkleTree::new();
    
    // Insert values
    tree.insert(b"key1", b"value1");
    tree.insert(b"key2", b"value2");
    
    // Retrieve values
    if let Some(value) = tree.get(b"key1") {
        println!("Found: {:?}", String::from_utf8_lossy(value));
    } else {
        println!("Key not found");
    }
    
    // Compute commitment
    let commitment = tree.compute_commitment();
    println!("Commitment: {:?}", hex::encode(commitment));
    
    // Verify commitment
    if tree.verify_commitment() {
        println!("Commitment is valid");
    } else {
        println!("Commitment verification failed");
    }
}
