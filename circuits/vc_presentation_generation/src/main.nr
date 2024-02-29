use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;

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

struct Credential {
    issuer: Issuer,
    subject: str<ISSUER_NAME_LEN>,
    subject_code: Field,
    claims: [Claim; MAX_CLAIMS],
    expired_date: u16,
    hash: Field,
    signature: Signature,
}

struct Claim {
    name: str<ATTRIBUTE_NAME_LEN>,
    code: Field,
    value: u8,
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

                if (condition.issuer == subCredential.issuer.name)
                    & (criteria.valid_date <= subCredential.expired_date) {
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
                }
                // println(credential.claims[j]);
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

fn main(criteria: AccessControlCriteria, credential: UnifiedCredential) -> pub (Field, Field) {
    // check the criteria
    // check_conditions(criteria, credential);

    let first_credential = credential.credentials[0];

    let mut claimHash = 0;

    for i in 0..first_credential.claims.len() {
        if (i == 0) {
            claimHash = poseidon::bn254::hash_2([first_credential.claims[i].code, first_credential.claims[i].value as Field]);
        } else {
            claimHash = poseidon::bn254::hash_3([claimHash, first_credential.claims[i].code, first_credential.claims[i].value as Field]);
        }
    }

    let calculated_hash = poseidon::bn254::hash_6(
        [
        first_credential.subject_code, first_credential.issuer.code, first_credential.issuer.public_key.x, first_credential.issuer.public_key.y, first_credential.expired_date as Field, claimHash
    ]
    );

    println(f"calculated_hash: {calculated_hash}");
    assert(calculated_hash == first_credential.hash);

    assert(
        eddsa_poseidon_verify(
            first_credential.issuer.public_key.x,
            first_credential.issuer.public_key.y,
            first_credential.signature.s,
            first_credential.signature.r8.x,
            first_credential.signature.r8.y,
            calculated_hash
        )
    );

    (calculated_hash, credential.credentials[0].hash)
}

#[test]
fn test_main() {
    // main(1, 2);
    // Uncomment to make test fail
    // main(1, 1);
}
