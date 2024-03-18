use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;

global MAX_CONDITIONS = 1;
global MAX_ISSUERS = 1;
global MAX_CREDENTIALS = 1;
global MAX_CLAIMS = 1;

global MAX_INPUT_SIBLINGS = 10;
global MAX_SIBLINGS = 128;

// global ATTRIBUTE_NAME_LEN = 10;
// global ISSUER_NAME_LEN = 8;

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

struct Condition {
    // name: str<ATTRIBUTE_NAME_LEN>,
    attr_code: Field,
    operator: str<2>,
    value: u8,
    issuer_codes: [Field; MAX_ISSUERS],
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



struct ExclusionMerkleTreeProof {
    siblings: [Field; MAX_INPUT_SIBLINGS],
    // root: Field,
    old_item: Field,
    is_old_0: Field,
}

impl ExclusionMerkleTreeProof {
    fn verify(self, hash: Field, root: Field)-> bool {
        let mut totalSiblings : [Field; MAX_SIBLINGS] = [0; MAX_SIBLINGS];
        for i in 0..self.siblings.len() {
            totalSiblings[i] = self.siblings[i];
        }

        smt::verifier::verifyExtended(1, root, self.old_item, self.old_item, self.is_old_0, hash, 0, 1, totalSiblings)
    }
}

struct Credential {
    // issuer: Issuer,
    // subject: str<ISSUER_NAME_LEN>,
    subject_code: Field,
    claims: [Claim; MAX_CLAIMS],
    expired_date: u16,
    // hash: Field,
    signature: Signature,
    non_revocation_proof: ExclusionMerkleTreeProof,
    issuer_index: Field,
}

impl Credential {
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

struct AccessControlCriteria {
    conditions: [Condition; MAX_CONDITIONS],
    predicates: [u8; MAX_CONDITIONS],
}

struct UnifiedCredential {
    credentials: [Credential; MAX_CREDENTIALS],
}