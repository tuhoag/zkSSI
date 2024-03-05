use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;

global MAX_CONDITIONS = 2;
global MAX_CLAIMS = 1;
global MAX_CREDENTIALS = 1;
global ATTRIBUTE_NAME_LEN = 10;
global ISSUER_NAME_LEN = 8;

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
    name: str<ATTRIBUTE_NAME_LEN>,
    operator: str<2>,
    value: u8,
    issuer: str<ISSUER_NAME_LEN>,
}

struct Issuer {
    name: str<ISSUER_NAME_LEN>,
    code: Field,
    public_key: PublicKey,
}

struct Claim {
    name: str<ATTRIBUTE_NAME_LEN>,
    code: Field,
    value: u8,
}

global MAX_INPUT_SIBLINGS = 10;
global MAX_SIBLINGS = 160;

struct ExclusionMerkleTreeProof {
    siblings: [Field; MAX_INPUT_SIBLINGS],
    root: Field,
    old_item: Field,
    is_old_0: Field,
}

impl ExclusionMerkleTreeProof {

    fn verify(self, hash: Field)-> bool {
        let mut totalSiblings : [Field; MAX_SIBLINGS] = [0; MAX_SIBLINGS];
        for i in 0..self.siblings.len() {
            totalSiblings[i] = self.siblings[i];
        }

        smt::verifier::verifyExtended(1, self.root, self.old_item, self.old_item, self.is_old_0, hash, 0, 1, totalSiblings)
    }

}

struct Credential {
    issuer: Issuer,
    subject: str<ISSUER_NAME_LEN>,
    subject_code: Field,
    claims: [Claim; MAX_CLAIMS],
    expired_date: u16,
    hash: Field,
    signature: Signature,
    non_revocation_proof: ExclusionMerkleTreeProof,
}



struct AccessControlCriteria {
    conditions: [Condition; MAX_CONDITIONS],
    combinations: [str<1>; (MAX_CONDITIONS - 1)],
    valid_date: u16,
}

struct UnifiedCredential {
    credentials: [Credential; MAX_CREDENTIALS],
}

fn check_conditions(criteria: AccessControlCriteria, credential: UnifiedCredential) {
    let mut previous_check = false;
    let mut current_check = false;

    for i in 0..criteria.conditions.len() {
        current_check = false;
        println(f"previous check: {previous_check} - current check: {current_check}");

        let condition = criteria.conditions[i];
        println(f"condition: {condition}");

        for j in 0..credential.credentials.len() {
            if (!current_check) {
                let subCredential = credential.credentials[j];

                if (condition.issuer == subCredential.issuer.name) & (criteria.valid_date <= subCredential.expired_date) {
                    for k in 0..subCredential.claims.len() {
                        let claim = subCredential.claims[k];

                        if (condition.name == claim.name) {
                            if condition.operator == "==" {
                                current_check = claim.value == condition.value;
                            } else if condition.operator == "!=" {
                                current_check = claim.value != condition.value;
                            } else {
                                let claim_value = claim.value as u8;
                                let condition_value = condition.value as u8;

                                println(claim_value);
                                println(condition_value);

                                if condition.operator == "> " {
                                    current_check = claim_value > condition_value;
                                } else if condition.operator == "< " {
                                    current_check = claim_value < condition_value;
                                } else if condition.operator == ">=" {
                                    current_check = claim_value >= condition_value;
                                } else if condition.operator == "<=" {
                                    current_check = claim_value <= condition_value;
                                } else {
                                    assert(false, "Operator is not supported");
                                    current_check = false;
                                }
                            }
                        }
                    }

                    if (current_check) {
                        let credential_hash = hash_credential(subCredential);

                        if (!subCredential.signature.verify(subCredential.issuer.public_key, credential_hash)) {
                            assert(false, "Signature is invalid");
                            current_check = false;
                        } else if (!subCredential.non_revocation_proof.verify(credential_hash)) {
                            assert(false, "Non Revocation Proof is invalid");
                            current_check = false;
                        }
                    }
                }
            }
        }

        let new_i: i8 = (i as i8) - (1 as i8);
        // println(new_i);
        if (new_i >= 0) {
            let operator = criteria.combinations[new_i];

            // println(new_i);

            if (operator == "&") {
                current_check = previous_check & current_check;
            } else if (operator == "|") {
                current_check = previous_check | current_check;
            } else {
                assert(false, "Combination Operator is not supported");
                current_check = false;
            }
            // println(operator);
            // println(current_check);
        }

        // assert(current_check);
        previous_check = current_check;
    }

    assert(current_check);
}

fn hash_credential(credential: Credential) -> Field {
    let mut claimHash = 0;

    for i in 0..credential.claims.len() {
        if (i == 0) {
            claimHash = poseidon::bn254::hash_2([credential.claims[i].code, credential.claims[i].value as Field]);
        } else {
            claimHash = poseidon::bn254::hash_3([claimHash, credential.claims[i].code, credential.claims[i].value as Field]);
        }
    }

    poseidon::bn254::hash_6(
        [
        credential.subject_code, credential.issuer.code, credential.issuer.public_key.x, credential.issuer.public_key.y, credential.expired_date as Field, claimHash
    ]
    )
}

fn check_signature(credential: Credential, calculated_hash: Field) -> bool {
    eddsa_poseidon_verify(
        credential.issuer.public_key.x,
        credential.issuer.public_key.y,
        credential.signature.s,
        credential.signature.r8.x,
        credential.signature.r8.y,
        calculated_hash
    )
}


fn main(criteria: AccessControlCriteria, credential: UnifiedCredential) {
    // check the criteria
    check_conditions(criteria, credential);
    // (calculated_hash, credential.credentials[0].hash)
}

#[test]
fn test_main() {
    // main(1, 2);
    // Uncomment to make test fail
    // main(1, 1);
}
