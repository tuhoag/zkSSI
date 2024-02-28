global MAX_CONDITIONS = 3;
global MAX_CLAIMS = 2;

struct Condition {
    name: str<10>,
    operator: str<2>,
    value: u8,
    issuer: str<8>,
}

struct Claim {
    name: str<10>,
    value: u8,
    issuer: str<8>,
    expired_date: u16,
}

struct AccessControlCriteria {
    conditions: [Condition; MAX_CONDITIONS],
    combinations: [str<1>; (MAX_CONDITIONS - 1)],
    valid_date: u16,
}

struct UnifiedCredential {
    claims: [Claim; MAX_CLAIMS],
}

fn check_conditions(criteria: AccessControlCriteria, credential: UnifiedCredential) {
    let mut previous_check = false;
    let mut current_check = false;

    for i in 0..criteria.conditions.len() {
        current_check = false;
        // println(f"previous check: {previous_check} - current check: {current_check}");

        // println(criteria.conditions[i]);

        for j in 0..credential.claims.len() {
            if (!current_check) {
                // println(credential.claims[j]);

                if (criteria.conditions[i].name == credential.claims[j].name) & (criteria.conditions[i].issuer == credential.claims[j].issuer) & (credential.claims[j].expired_date >= criteria.valid_date) {
                    if criteria.conditions[i].operator == "= " {
                        current_check = credential.claims[j].value == criteria.conditions[i].value;
                    } else if criteria.conditions[i].operator == "!=" {
                        current_check = credential.claims[j].value != criteria.conditions[i].value;
                    } else {
                        let claim_value = credential.claims[j].value as u8;
                        let condition_value = criteria.conditions[i].value as u8;

                        // println(claim_value);
                        // println(condition_value);

                        if criteria.conditions[i].operator == "> " {
                            current_check = claim_value > condition_value;
                        } else if criteria.conditions[i].operator == "< " {
                            current_check = claim_value < condition_value;
                        } else if criteria.conditions[i].operator == ">=" {
                            current_check = claim_value >= condition_value;
                        } else if criteria.conditions[i].operator == "<=" {
                            current_check = claim_value <= condition_value;
                        } else {
                            assert(false, "Operator is not supported");
                            current_check = false;
                        }

                        // println(current_check);
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
