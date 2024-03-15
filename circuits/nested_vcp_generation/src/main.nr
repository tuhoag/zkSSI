use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;
use dep::zkvc::{AccessControlCriteria, UnifiedCredential, Credential};

global TREE_LENGTH = 8;
global NEW_MAX_CONDITIONS = 5;



fn check_conditions(validations: [bool; NEW_MAX_CONDITIONS], predicates: [Node; NEW_MAX_CONDITIONS], current: Field) {
    let left = current * 2 + 1;
    let right = current * 2 + 2;

    if current != 0 {
        validations[current - 2]
    }

}

struct Validation {
    validations: [bool; 5],
    predicates: [u8; 5]
}

impl Validation {
    fn validate(self, current_index: u8) -> bool {
        let mut result = false;

        if self.predicates[current_index] >= 2 {
            result = self.validations[current_index - 2];
        } else if self.predicates[current_index] == 0 {
            result = self.validate(current_index * 2 + 1) & self.validate(current_index * 2 + 2);
        } else {
            result = self.validate(current_index * 2 + 1) | self.validate(current_index * 2 + 2);
        }

        result
    }
}

struct Node {
    value: u8,
    left: Node,
    right: Node,
}

fn validate(validations: [bool; 5], predicates: [u8; 5], current_index: u8)-> bool {
    let mut result = false;

    if predicates[current_index] >= 2 {
        result = validations[current_index - 2];
    } else if predicates[current_index] == 0 {
        result = validate(validations, predicates, current_index * 2 + 1) & validate(validations, predicates, current_index * 2 + 2);
    } else {
        result = validate(validations, predicates, current_index * 2 + 1) | validate(validations, predicates, current_index * 2 + 2);
    }

    result
}

fn validate2(predicates: [u8; 5], current_index: u8)-> bool {
    println(current_index);

    let mut result = false;

    if predicates[current_index] >= 2 {
        result = predicates[current_index - 2] == 3;
    } else if predicates[current_index] == 0 {
        result = validate2(predicates, current_index * 2 + 1) & validate2(predicates, current_index * 2 + 2);
    } else {
        result = validate2(predicates, current_index * 2 + 1) | validate2(predicates, current_index * 2 + 2);
    }

    result
}

fn validate3(validations: [bool; 5], predicates: [u8; 5])-> bool {
    let mut results: [bool; 5] = [true; 5];

    let mut current_index = predicates.len() - 1;
    let mut derived_index = 0;
    let mut i: u64 = 0;

    println(results);
    for j in 0..5 {
        i = 5 - j - 1;

        println(i);
        if predicates[i] >= 2 {
            results[i] = validations[predicates[i] - 2];
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


fn main(num: Field) {
    // check the criteria
    let mut validations = [true, false, true, false, false];
    let mut predicates = [1, 0, 2, 3, 4];

    let result = validate3(validations, predicates);
    println(result);
}