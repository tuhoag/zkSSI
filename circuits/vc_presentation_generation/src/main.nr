global MAX_CONDITIONS = 3;
global MAX_CLAIMS = 2;
global MAX_CREDENTIALS = 2;

struct Condition {
    name: str<11>,
    operator: str<2>,
    value: u8,
    issuer: str<8>,
}

struct Credential {
    issuer: str<8>,
    claims: [Claim; MAX_CLAIMS],
    expired_date: u16,
}

struct Claim {
    name: str<11>,
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

                if (condition.issuer == subCredential.issuer) & (criteria.valid_date <= subCredential.expired_date) {
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

fn main(criteria: AccessControlCriteria, credential: UnifiedCredential) {
    // check the criteria
    check_conditions(criteria, credential);
}

#[test]
fn test_main() {
    // main(1, 2);
    // Uncomment to make test fail
    // main(1, 1);
}
