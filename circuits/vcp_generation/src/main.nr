use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;
use dep::zkvc::{AccessControlCriteria, UnifiedCredential, Condition, Credential, Issuer};

global MAX_CONDITIONS = 1;
global MAX_PREDICATES = 1;
global MAX_CREDENTIALS = 1;
global MAX_ISSUERS = 1;
global MAX_CLAIMS = 1;

global MAX_INPUT_SIBLINGS = 32;



fn validate_conditions(conditions: [Condition<MAX_ISSUERS>; MAX_CONDITIONS], credentials: [Credential<MAX_CLAIMS,MAX_INPUT_SIBLINGS>; MAX_CREDENTIALS], public_keys: [Issuer; MAX_CREDENTIALS], proving_time: u8, revocation_roots: [Field; MAX_CREDENTIALS]) -> [bool; MAX_CONDITIONS] {
    let mut credential_validations = [true; MAX_CREDENTIALS];
    let mut condition_validations = [false; MAX_CONDITIONS];

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
        // println(f"condition: {condition}");

        for vcIndex in 0..credentials.len() {
            if (!current_check) {
                let current_credential = credentials[vcIndex];
                let current_issuer = public_keys[current_credential.issuer_index];

                if (condition.issuer_codes.any(|issuer_code| issuer_code == current_issuer.issuer_code) & credential_validations[vcIndex]) {
                    // check claims
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

                                // println(claim_value);
                                // println(condition_value);

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

                    // if (current_check) {
                    //     let mut credential_validity = true;

                    //     if (!is_credential_checked[vcIndex]) {
                    //         is_credential_checked[vcIndex] = true;

                    //         let credential_hash = current_credential.calculate_hash(current_issuer);

                    //         if (proving_time > current_credential.expired_date) {
                    //             assert(false, "Certificate is expired");
                    //             credential_validity = false;
                    //         } else if (!current_credential.signature.verify(current_issuer.public_key, credential_hash)) {
                    //             assert(false, "Signature is invalid");
                    //             credential_validity = false;
                    //         } else if (!current_credential.non_revocation_proof.verify(credential_hash, revocation_roots[vcIndex])) {
                    //             assert(false, "Non Revocation Proof is invalid");
                    //             credential_validity = false;
                    //         }

                    //         credential_validations[vcIndex] = credential_validity;
                    //     } else {
                    //         credential_validity = credential_validations[vcIndex];
                    //     }

                    //     if (!credential_validity) {
                    //         current_check = false;
                    //     }
                    // }
                }
            }
        }

        condition_validations[i] = current_check;
    }

    condition_validations
}

fn validate_predicates(predicates: [u8; MAX_PREDICATES], condition_validations: [bool; MAX_CONDITIONS]) -> bool {
    let mut results = [true; MAX_PREDICATES];
    let mut i: u64 = 0;

    // println(results);
    for j in 0..MAX_PREDICATES {
        i = MAX_PREDICATES - j - 1;

        // println(i);
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

        // println(results);
    }

    results[0]
}

fn main(criteria: AccessControlCriteria<MAX_CONDITIONS,MAX_ISSUERS,MAX_PREDICATES>, credentials: [Credential<MAX_CLAIMS,MAX_INPUT_SIBLINGS>; MAX_CREDENTIALS], public_keys: pub [Issuer; MAX_ISSUERS], proving_time: pub u8, revocation_roots: pub [Field; MAX_CREDENTIALS]) {
    let condition_validations = validate_conditions(criteria.conditions, credentials, public_keys, proving_time, revocation_roots);

    // condition_validations
    // assert(condition_validations == [true, true]);
    // println(condition_validations);

    // let condition_validations = [true; MAX_CONDITIONS];
    let verification = validate_predicates(criteria.predicates, condition_validations);

    assert(verification == true);

    // condition_validations
}
