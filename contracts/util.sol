// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.24;

struct Point {
    bytes32 x;
    bytes32 y;
}
struct Condition {
    bytes32 attrCode;
    uint8 operator;
    uint8 value;
    uint8[] issuerIds;
}

// attr_code: Field,
//     operator: u8,
//     value: u8,
//     issuer_codes: [Field; I],

struct Requirement {
    // conditions
    Condition[] conditions;

    // predicates
    uint8[] predicates;
}

struct PublicKey {
    bytes32 issuerCode;
    Point publicKey;
}

struct PublicKeys {
    PublicKey[] publicKeys;
}