use custom_verkle::VerkleTree;

fn main() {
    let mut tree = VerkleTree::new();
    
    // Insert values
    tree.insert(b"key1", b"value1");
    tree.insert(b"key2", b"value2");
    tree.insert(b"64d9f1cf9079ebe514609550e3fd51e7a75ee11ece137f39fb64ccb31d720bbc", b"squirrel");
    tree.insert(b"64d9f1dog", b"dog");
    
    // Retrieve values
    if let Some(value) = tree.get(b"key1") {
        println!("Found: {:?}", String::from_utf8_lossy(value));
    } else {
        println!("Key not found");
    }

    // Test consistency
    if let Some(value) = tree.get(b"unknown_key") {
        println!("Found: {:?}", String::from_utf8_lossy(value));
    } else {
        println!("Key not found");
    }
    
    // Compute commitment
    let commitment = tree.compute_commitment();
    println!("Commitment: {:?}", commitment);
    
    // Verify commitment
    if tree.verify_root() {
        println!("Commitment is valid");
    } else {
        println!("Commitment verification failed");
    }

    // Generate proof for a key1
    if let Some(((key, value), proof, root_commitment)) = tree.generate_proof(b"key1") {
        println!("Proof for {:?}: is valid ?", String::from_utf8_lossy(&key));
        println!("Root Commitment: {:?}", root_commitment);
    } else {
        println!("No proof found for key");
    }
    
    // Generate proof for a key2
    if let Some(((key, value), proof, root_commitment)) = tree.generate_proof(b"key2") {
        println!("Proof for {:?}: is valid ?", String::from_utf8_lossy(&key));
    } else {
        println!("No proof found for key");
    }
    
    // Generate proof for a 64d9f1dog
    if let Some(((key, value), proof, root_commitment)) = tree.generate_proof(b"64d9f1dog") {
        println!("Proof for {:?}: is valid ?", String::from_utf8_lossy(&key));
    } else {
        println!("No proof found for key");
    }

    // Generate proof for a unknown_key
    if let Some(((key, value), proof, root_commitment)) = tree.generate_proof(b"unknown_key") {
        println!("Proof for {:?}: is valid ?", String::from_utf8_lossy(&key));
    } else {
        println!("No proof found for key");
    }
    // println!("Tree: {:?}", tree);
}
