use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;

global EQUAL = 0;
global NOT_EQUAL = 1;
global GREATER_THAN = 2;
global LESS_THAN = 3;
global GREATER_THAN_OR_EQUAL = 4;
global LESS_THAN_OR_EQUAL = 5;


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
    operator: u8,
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
    is_old_0: u8,
}

impl<T> ExclusionMerkleTreeProof<T> {
    fn verify(self, hash: Field, root: Field)-> bool {
        // let mut totalSiblings : [Field; MAX_SIBLINGS] = [0; MAX_SIBLINGS];
        // for i in 0..self.siblings.len() {
        //     totalSiblings[i] = self.siblings[i];
        // }

        smt::verifier::verifyExtended(1, root, self.old_item, self.old_item, self.is_old_0 as Field, hash, 0, 1, self.siblings)
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

pub fn validate_conditions<I, CO, C, T, CE>(
    conditions: [Condition<I>; CO],
    credentials: [Credential<C,T>; CE],
    public_keys: [Issuer; CE],
    proving_time: u8,
    revocation_roots: [Field; CE]
) -> [bool; CO] {
    let mut credential_validations = [true; CE];
    let mut condition_validations = [false; CO];

    for vcIndex in 0..credentials.len() {
        let current_credential = credentials[vcIndex];
        let current_issuer = public_keys[current_credential.issuer_index];
        let mut credential_validity = true;

        let credential_hash = current_credential.calculate_hash(current_issuer);

        if (proving_time > current_credential.expired_date) {
            assert(false, "Certificate is expired");
            credential_validity = false;
        } else if (!current_credential.signature.verify(current_issuer.public_key, credential_hash)) {
            assert(false, "Signature is invalid");
            credential_validity = false;
        } else if (!current_credential.non_revocation_proof.verify(credential_hash, revocation_roots[vcIndex])) {
            assert(false, "Non Revocation Proof is invalid");
            credential_validity = false;
        }

        credential_validations[vcIndex] = credential_validity;
    }

    for i in 0..conditions.len() {
        let mut current_check = false;
        let condition = conditions[i];

        for vcIndex in 0..credentials.len() {
            if (!current_check) {
                let current_credential = credentials[vcIndex];
                let current_issuer = public_keys[current_credential.issuer_index];

                if (condition.issuer_codes.any(|issuer_code| issuer_code == current_issuer.issuer_code)
                    & credential_validations[vcIndex]) {
                    // check claims
                    for k in 0..current_credential.claims.len() {
                        let claim = current_credential.claims[k];

                        if (condition.attr_code == claim.code) {
                            if condition.operator == EQUAL {
                                current_check = claim.value == condition.value;
                            } else if condition.operator == NOT_EQUAL {
                                current_check = claim.value != condition.value;
                            } else {
                                let claim_value = claim.value as u8;
                                let condition_value = condition.value as u8;

                                if condition.operator == GREATER_THAN {
                                    current_check = claim_value > condition_value;
                                } else if condition.operator == LESS_THAN {
                                    current_check = claim_value < condition_value;
                                } else if condition.operator == GREATER_THAN_OR_EQUAL {
                                    current_check = claim_value >= condition_value;
                                } else if condition.operator == LESS_THAN_OR_EQUAL {
                                    current_check = claim_value <= condition_value;
                                } else {
                                    assert(false, "Operator is not supported");
                                    current_check = false;
                                }
                            }
                        }
                    }
                }
            }
        }

        condition_validations[i] = current_check;
    }

    condition_validations
}

pub fn validate_predicates<P,CO>(
    predicates: [u8; P],
    condition_validations: [bool; CO]
) -> bool {
    let mut results = [true; P];
    let mut i: u64 = 0;

    for j in 0..P {
        i = P - j - 1;

        if predicates[i] >= 2 {
            results[i] = condition_validations[predicates[i] - 2];
        } else if predicates[i] == 0 {
            results[i] = results[i * 2 + 1] & results[i * 2 + 2];
        } else {
            results[i] = results[i * 2 + 1] | results[i * 2 + 2];
        }
    }

    results[0]
}