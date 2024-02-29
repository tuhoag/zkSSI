use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;

struct PublicKey {
    x : Field,
    y : Field,
}

struct Signature {
    s: Field,
    r8_x: Field,
    r8_y: Field,
}

fn main(
    message: pub [Field; 2],
    public_key: pub PublicKey,
    hash: pub Field,
    signature: pub Signature
) -> pub Field {
    let calculated_hash = poseidon::bn254::hash_2(message);

    println(f"calculated_hash: {calculated_hash}");

    assert(calculated_hash == hash);

    assert(
        eddsa_poseidon_verify(
            public_key.x,
            public_key.y,
            signature.s,
            signature.r8_x,
            signature.r8_y,
            hash
        )
    );

    calculated_hash
}
