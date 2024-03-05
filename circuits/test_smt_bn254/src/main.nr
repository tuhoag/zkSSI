use dep::smt::{verify, TREE_DEPTH};

struct ExclusionMerkleTreeProof {
    siblings: [Field; 10],
    matching_entry: [Option<Field>; 2],
    root: Field,
}


fn main(hash: pub Field, proof: ExclusionMerkleTreeProof) {
    let mut totalSiblings : [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let start_index = TREE_DEPTH as Field - 10;
    for i in 0..proof.siblings.len() {
        totalSiblings[start_index + i] = proof.siblings[i];
    }
    verify([hash, hash], proof.matching_entry, totalSiblings, proof.root);

    // verify([hash, hash], proof.matching_entry, proof.siblings, proof.root);

}