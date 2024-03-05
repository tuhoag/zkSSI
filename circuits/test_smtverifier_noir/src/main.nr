use dep::smt;

global MAX_INPUT_SIBLINGS = 10;
global MAX_SIBLINGS = 160;
struct ExclusionMerkleTreeProof {
    siblings: [Field; MAX_INPUT_SIBLINGS],
    root: Field,
    old_item: Field,
    is_old_0: Field,
}

// fn main(hash: Field, root: Field, siblings: [Field; 160]) {

//     smt::verifier::verify(root, key, value, siblings);
// }
// pub fn verifyExtended<N>(enabled : Field, root : Field, oldKey : Field, oldValue : Field, isOld0 : Field, key : Field, value : Field, fnc : Field, siblings : [Field; N])
fn main(
    proof: ExclusionMerkleTreeProof,
    key: Field,
    // // enabled : Field,
    // root : Field,
    // old_item : Field,
    // // oldValue : Field,
    // is_old_0 : Field,
    // key : Field,
    // // value : Field,
    // // fnc : Field,
    // siblings : [Field; MAX_INPUT_SIBLINGS]
    ) {
    let mut totalSiblings : [Field; MAX_SIBLINGS] = [0; MAX_SIBLINGS];
    for i in 0..proof.siblings.len() {
        totalSiblings[i] = proof.siblings[i];
    }
    smt::verifier::verifyExtended(1, proof.root, proof.old_item, proof.old_item, proof.is_old_0, key, 0, 1, totalSiblings)
}