use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;

struct Point {
    x: Field,
    y: Field,
}

type PublicKey = Point;

struct Signature {
    s: Field,
    r8: Point,
}

impl Signature {
    fn verify(self, public_key: PublicKey, hash: Field) -> bool {
        eddsa_poseidon_verify(
            public_key.x,
            public_key.y,
            self.s,
            self.r8.x,
            self.r8.y,
            hash
        )
    }
}

struct Condition<I> {
    // name: str<ATTRIBUTE_NAME_LEN>,
    attr_code: Field,
    operator: str<2>,
    value: u8,
    issuer_codes: [Field; I],
}

struct Issuer {
    // name: str<ISSUER_NAME_LEN>,
    issuer_code: Field,
    public_key: PublicKey,
}

struct Claim {
    // name: str<ATTRIBUTE_NAME_LEN>,
    code: Field,
    value: u8,
}


struct ExclusionMerkleTreeProof<T> {
    siblings: [Field; T],
    // root: Field,
    old_item: Field,
    is_old_0: Field,
}

impl<T> ExclusionMerkleTreeProof<T> {
    fn verify(self, hash: Field, root: Field)-> bool {
        // let mut totalSiblings : [Field; MAX_SIBLINGS] = [0; MAX_SIBLINGS];
        // for i in 0..self.siblings.len() {
        //     totalSiblings[i] = self.siblings[i];
        // }

        smt::verifier::verifyExtended(1, root, self.old_item, self.old_item, self.is_old_0, hash, 0, 1, self.siblings)
    }
}

struct Credential<C,T> {
    // issuer: Issuer,
    // subject: str<ISSUER_NAME_LEN>,
    subject_code: Field,
    claims: [Claim; C],
    expired_date: u8,
    // hash: Field,
    signature: Signature,
    non_revocation_proof: ExclusionMerkleTreeProof<T>,
    issuer_index: u8,
}

impl<C,T> Credential<C,T> {
    fn calculate_hash(self, issuer: Issuer) -> Field {
        let mut claimHash = 0;

        for i in 0..self.claims.len() {
            if (i == 0) {
                claimHash = poseidon::bn254::hash_2([self.claims[i].code, self.claims[i].value as Field]);
            } else {
                claimHash = poseidon::bn254::hash_3([claimHash, self.claims[i].code, self.claims[i].value as Field]);
            }
        }

        poseidon::bn254::hash_6(
            [
            self.subject_code, issuer.issuer_code, issuer.public_key.x, issuer.public_key.y, self.expired_date as Field, claimHash
        ]
        )
    }
}

struct AccessControlCriteria<CO,I,P> {
    conditions: [Condition<I>; CO],
    predicates: [u8; P],
}

struct UnifiedCredential<C,T,CE> {
    credentials: [Credential<C,T>; CE],
}