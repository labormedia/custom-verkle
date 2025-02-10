use custom_verkle::VerkleTree;
use curve25519_dalek::RistrettoPoint;

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
    let unknown_key = b"unknown_key";
    if let Some(value) = tree.get(unknown_key) {
        println!("Found: {:?}", String::from_utf8_lossy(value));
    } else {
        println!("Key \"{}\" not found", String::from_utf8_lossy(unknown_key));
    }
    
    // Compute commitment
    println!("Computing commitment");
    let commitment = tree.compute_commitment();
    // println!("Commitment: {:?}", commitment);
    
    // Verify commitment
    if tree.verify_root() {
        println!("Commitment is valid");
    } else {
        println!("Commitment verification failed");
    }

    // Generate proof for a key1
    if let Some(((key, value), proof, node_commitment)) = tree.generate_proof(b"key1") {
        println!("Proof for {:?}: is valid with length {}", String::from_utf8_lossy(&key), proof.len());
        assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &node_commitment));
    } else {
        println!("No proof found for key");
    }
    
    // Generate proof for a key2
    if let Some(((key, value), proof, node_commitment)) = tree.generate_proof(b"key2") {
        println!("Proof for {:?}: is valid with length {}", String::from_utf8_lossy(&key), proof.len());
        assert!(VerkleTree::verify_pedersen_commitment(&key, &value, &node_commitment));
    } else {
        println!("No proof found for key");
    }
    
    // Generate proof for a key2
    if let Some(((key, value), proof, node_commitment)) = tree.generate_proof(b"key") {
        println!("Proof for {:?}: is valid with length {}", String::from_utf8_lossy(&key), proof.len());
        assert!(!VerkleTree::verify_pedersen_commitment(&key, &value, &node_commitment));
    } else {
        println!("No proof found for key");
    }
    
    // Generate proof for a 64d9f1dog
    let key_lookup = b"64d9f1dog";
    if let Some(((key, value), proof, node_commitment)) = tree.generate_proof(key_lookup) {
        println!("Proof for {:?}: is valid with length {}", String::from_utf8_lossy(key_lookup), proof.len());
        let (_, r) = node_commitment.tuple();
        for byte in key_lookup {
            let ristretto = VerkleTree::commit(&key, &tree.get(&key).unwrap(), r);
            assert_eq!( node_commitment, (ristretto, r).into() );
        }
    } else {
        println!("No proof found for key");
    }

    // Generate proof for a unknown_key
    let unknown_key = b"unknown_key";
    if let Some(((key, value), proof, node_commitment)) = tree.generate_proof(unknown_key) {
        println!("Proof for {:?}: is valid with length {}", String::from_utf8_lossy(unknown_key), proof.len());
    } else {
        println!("No proof found for key \"{}\"", String::from_utf8_lossy(unknown_key));
    }
    
    let root_commitment = tree.compute_commitment();
    let new_key = b"64d9f1cf9079ebe514609550e3fd51e7a7";
    tree.insert(new_key, b"cat");
    let new_root_commitment = tree.compute_commitment();
    assert!(tree.verify_root());
    //assert_ne!(root_commitment, new_root_commitment );
    if let Some(((key, value), proof, node_commitment)) = tree.generate_proof(new_key) {
        println!("Proof length {}", proof.len());
        //assert_eq!(new_root_commitment - proof.into_iter().map(|x| { x.0 } ).sum::<RistrettoPoint>() , VerkleTree::commit(&key, &value, node_commitment.1) );
    } else {
        println!("No proof found for key \"{}\"", String::from_utf8_lossy(new_key));
    };
    
}