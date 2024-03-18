use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;
use dep::zkvc::{AccessControlCriteria, UnifiedCredential, Condition, Credential, Issuer, MAX_CREDENTIALS, MAX_CONDITIONS};

fn validate_conditions(conditions: [Condition; MAX_CONDITIONS], credentials: [Credential; MAX_CREDENTIALS], public_keys: [Issuer; MAX_CREDENTIALS], proving_time: u16, revocation_roots: [Field; MAX_CREDENTIALS]) -> [bool; MAX_CONDITIONS] {
    let mut condition_validations = [false; MAX_CONDITIONS];

    for i in 0..conditions.len() {
        let mut current_check = false;
        // println(f"previous check: {previous_check} - current check: {current_check}");

        let condition = conditions[i];
        println(f"condition: {condition}");

        for vcIndex in 0..credentials.len() {
            if (!current_check) {
                let current_credential = credentials[vcIndex];
                let current_issuer = public_keys[current_credential.issuer_index];

                if (condition.issuer_codes.any(|issuer_code| issuer_code == current_issuer.issuer_code)) & (proving_time <= current_credential.expired_date) {
                    for k in 0..current_credential.claims.len() {
                        let claim = current_credential.claims[k];

                        if (condition.attr_code == claim.code) {
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
                        let credential_hash = current_credential.calculate_hash(current_issuer);

                        if (!current_credential.signature.verify(current_issuer.public_key, credential_hash)) {
                            assert(false, "Signature is invalid");
                            current_check = false;
                        } else if (!current_credential.non_revocation_proof.verify(credential_hash, revocation_roots[vcIndex])) {
                            assert(false, "Non Revocation Proof is invalid");
                            current_check = false;
                        }
                    }
                }
            }
        }

        condition_validations[i] = current_check;
    }

    condition_validations
}

fn validate_predicates(predicates: [u8; MAX_CONDITIONS], condition_validations: [bool; MAX_CONDITIONS]) -> bool {
    let mut results = [true; MAX_CONDITIONS];
    let mut i: u64 = 0;

    println(results);
    for j in 0..MAX_CONDITIONS {
        i = MAX_CONDITIONS - j - 1;

        println(i);
        if predicates[i] >= 2 {
            results[i] = condition_validations[predicates[i] - 2];
        } else {
            // derived_index = (i - 2) / 2;
            // println(derived_index);
            if predicates[i] == 0 {
                results[i] = results[i * 2 + 1] & results[i * 2 + 2];
            } else {
                results[i] = results[i * 2 + 1] | results[i * 2 + 2];
            }
        }

        println(results);
    }

    results[0]
}

fn main(criteria: AccessControlCriteria, credentials: [Credential; MAX_CREDENTIALS], public_keys: [Issuer; MAX_CREDENTIALS], proving_time: u16, revocation_roots: [Field; MAX_CREDENTIALS]) {
    let condition_validations = validate_conditions(criteria.conditions, credentials, public_keys, proving_time, revocation_roots);

    let condition_validations = [true; MAX_CONDITIONS];
    let verification = validate_predicates(criteria.predicates, condition_validations);

    assert(verification == true);
}
