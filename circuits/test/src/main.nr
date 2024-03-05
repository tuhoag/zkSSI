use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt::{TREE_DEPTH, verify, add};
use dep::smt::utils;

struct PublicKey {
    x : Field,
    y : Field,
}

struct Signature {
    s: Field,
    r8_x: Field,
    r8_y: Field,
}

struct ExclusionMerkleTreeProof {
    siblings: [Field; TREE_DEPTH],
    matching_entry: [Option<Field>; 2],
    root: Field,
}

impl ExclusionMerkleTreeProof {
    fn verify(self, entry: [Field; 2]) -> bool {
        print("root:");
        println(self.root);

        // let matching_entry = [Option::some(self.matching_entry[0]), Option::some(self.matching_entry[1])];
        let mut calculated_root: Field = 0;
        let path = utils::key_to_path(entry[0]);

        // assert(self.matching_entry[0].is_none());
        // if there is no matching_entry it is a membership proof
        // if there is a matching_entry it is a non_membership proof
        if self.matching_entry[0].is_none() | self.matching_entry[1].is_none() {
            println("Membership proof");
            // membership proof: the root is calculated based on the entry, the siblings,
            // and the path determined by the key of entry through consecutive hashing
            calculated_root = utils::calculcate_root(entry, self.siblings, path);
            println(f"calculated root: {calculated_root}");
        } else {
            println("Non membership proof");
            // non-membership proof: the root is calculated based on the matching_entry, the siblings
            // and the path that is determined by the key of entry. This makes sure that matching_entry is in fact
            // a matching entry for entry meaning that it shares the same first bits as path
            calculated_root = utils::calculcate_root([self.matching_entry[0].unwrap(), self.matching_entry[1].unwrap()], self.siblings, path);

            println(f"calculated root: {calculated_root}");
        }

        // println(f"calculated root: {calculated_root}");
        // println(f"root: {self.root}");


        // println(self.root);

        calculated_root == self.root
        // verify([calculated_hash, calculated_hash], proof.matching_entry, proof.siblings, root);
        // true
    }
}

struct NonRevocationProof {
    proof: ExclusionMerkleTreeProof,
    revocation_tree_root: Field,
}

fn test_my_tree() {
    let hashes = [
        7853200120776062878684798364095072458815029376092732009249414926327459813530,
        17197790661637433027297685226742709599380837544520340689137581733613433332983,
        14763215145315200506921711489642608356394854266165572616578112107564877678998,
    ];

    let entry = [hashes[0], hashes[0]];
    let mut siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let zero_node = 0;

    let first_root = add([hashes[0], hashes[0]], zero_node, siblings);
    println(f"first_root: {first_root}");

    siblings[255] = first_root;
    let second_root = add([hashes[1], hashes[1]], first_root, siblings);
    println(f"second_root: {second_root}");

    // let first_proof =
}


fn main(
    // message: [Field; 2],
    // public_key: PublicKey,
    hash: Field,
    // signature: Signature,
    proof: ExclusionMerkleTreeProof,
    // temp: pub Option<Field>
) {
    // test_my_tree();
    // let calculated_hash = poseidon::bn254::hash_2(message);

    // // println(f"calculated_hash: {calculated_hash}");

    // assert(calculated_hash == hash, "Hash is invalid");


    // assert(
    //     eddsa_poseidon_verify(
    //         public_key.x,
    //         public_key.y,
    //         signature.s,
    //         signature.r8_x,
    //         signature.r8_y,
    //         hash
    //     ), "Signature is invalid"
    // );


    assert(proof.verify([hash, hash]), "merkle proof is invalid");
    // verify([calculated_hash, calculated_hash], proof.matching_entry, proof.siblings, root);

    // calculated_hash
    // assert(temp.is_some());
}

#[test]
fn test_my_membership_proof() {
    let hashes = [
        7853200120776062878684798364095072458815029376092732009249414926327459813530,
        17197790661637433027297685226742709599380837544520340689137581733613433332983,
        14763215145315200506921711489642608356394854266165572616578112107564877678998,
    ];

    let entry = [hashes[0], hashes[0]];
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let zero_node = 0;
    add(entry, zero_node, siblings);
    // assert(
    //     add(entry, zero_node, siblings)
    //     == 7842913321420301106140788486336995496832503825951977327575501561489697540557
    // );

}

#[test]
fn test_verify_membership_proof() {
    let small_tree_root = 3532809757480436997969526334543526996242857122876262144596246439822675654128;
    let key = 18746990989203767017840856832962652635369613415011636432610873672704085238844;
    let value = 10223238458026721676606706894638558676629446348345239719814856822628482567791;
    let entry = [key, value];
    let matching_entry = [Option::none(), Option::none()];
    let mut siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    siblings[254] = 18126944477260144816572365299295230808286197301459941187567621915186392922196;
    siblings[255] = 7842913321420301106140788486336995496832503825951977327575501561489697540557;
    verify(entry, matching_entry, siblings, small_tree_root);
}

#[test]
fn test_verify_non_membership_proof() {
    let small_tree_root = 3532809757480436997969526334543526996242857122876262144596246439822675654128;
    let key = 8459688297517826598613412977307486050019239051864711035321718508109192087854;
    let value = 8510347201346963732943571140849185725417245763047403804445415726302354045170;
    let entry = [key, value];
    let matching_entry = [
        Option::some(13924553918840562069536446401916499801909138643922241340476956069386532478098),
        Option::some(13761779908325789083343687318102407319424329800042729673292939195255502025802)
    ];
    let mut siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    siblings[254] = 14443001516360873457302534246953033880503978184674311810335857314606403404583;
    siblings[255] = 7842913321420301106140788486336995496832503825951977327575501561489697540557;
    verify(entry, matching_entry, siblings, small_tree_root);
}

#[test]
fn test_add_first_element() {
    let key = 20438969296305830531522370305156029982566273432331621236661483041446048135547;
    let value = 17150136040889237739751319962368206600863150289695545292530539263327413090784;
    let entry = [key, value];
    let siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    let zero_node = 0;
    assert(
        add(entry, zero_node, siblings)
        == 7842913321420301106140788486336995496832503825951977327575501561489697540557
    );
}

#[test]
fn test_add_element_to_one_element_tree() {
    let key = 8459688297517826598613412977307486050019239051864711035321718508109192087854;
    let value = 8510347201346963732943571140849185725417245763047403804445415726302354045170;
    let entry = [key, value];
    let old_root = 7842913321420301106140788486336995496832503825951977327575501561489697540557;
    let mut siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    siblings[255] = 7842913321420301106140788486336995496832503825951977327575501561489697540557;
    assert(
        add(entry, old_root, siblings)
        == 6309163561753770186763792861087421800063032915545949912480764922611421686766
    );
}

#[test]
fn test_add_element_to_existing_tree() {
    let key = 8459688297517826598613412977307486050019239051864711035321718508109192087854;
    let value = 8510347201346963732943571140849185725417245763047403804445415726302354045170;
    let entry = [key, value];
    let small_tree_root = 3532809757480436997969526334543526996242857122876262144596246439822675654128;
    let mut siblings: [Field; TREE_DEPTH] = [0; TREE_DEPTH];
    siblings[253] = 18126944477260144816572365299295230808286197301459941187567621915186392922196;
    siblings[254] = 14443001516360873457302534246953033880503978184674311810335857314606403404583;
    siblings[255] = 7842913321420301106140788486336995496832503825951977327575501561489697540557;
    let big_tree_root = 4657474665007910823901096287220097081233671466281873230928277896829046731272;
    assert(add(entry, small_tree_root, siblings) == big_tree_root);
}
