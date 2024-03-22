use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;
use dep::zkvc::{AccessControlCriteria, UnifiedCredential, Condition, Credential, Issuer, validate_conditions, validate_predicates};


global MAX_CLAIMS = 1;
global MAX_CONDITION_ISSUERS = 1;

// 1 CONDITION
// global MAX_CONDITIONS = 1;
// global MAX_CREDENTIALS = 1;
// global MAX_ISSUERS = 1;
// global MAX_PREDICATES = 1;

// 2 CONDITIONS
global MAX_CONDITIONS = 2;
global MAX_CREDENTIALS = 2;
global MAX_ISSUERS = 2;
global MAX_PREDICATES = 3;

// 3 CONDITIONS
// global MAX_CONDITIONS = 3;
// global MAX_CREDENTIALS = 3;
// global MAX_ISSUERS = 3;
// global MAX_PREDICATES = 5;

// 4 CONDITIONS
// global MAX_CONDITIONS = 4;
// global MAX_CREDENTIALS = 4;
// global MAX_ISSUERS = 4;
// global MAX_PREDICATES = 7;

// 5 CONDITIONS
// global MAX_CONDITIONS = 5;
// global MAX_CREDENTIALS = 5;
// global MAX_ISSUERS = 5;
// global MAX_PREDICATES = 9;

global MAX_SIBLINGS = 32;

fn test(criteria: AccessControlCriteria<MAX_CONDITIONS,MAX_CONDITION_ISSUERS,MAX_PREDICATES>,
    credentials: [Credential<MAX_CLAIMS,MAX_SIBLINGS>; MAX_CREDENTIALS],
    public_keys: [Issuer; MAX_ISSUERS],
    proving_time: u8,
    revocation_roots: [Field; MAX_CREDENTIALS]) {
    assert(proving_time == 0);
    assert(revocation_roots.len() == MAX_CREDENTIALS);
    for i in 0..MAX_CREDENTIALS {
        assert(revocation_roots[i] == 0);
    }

    assert(public_keys[0].issuer_code == 0x6973737565723030);
    assert(public_keys[0].public_key.x == 0x2601ded51b3d232bb40791f4761b34da7170c680dc1f27d87a8970320de932f8);
    assert(public_keys[0].public_key.y == 0x1e67325076cea0b9af317ff09627610d24ef943cce4da5dcf1c15b126b04911f);

    assert(public_keys[1].issuer_code == 0x6973737565723031);
    assert(public_keys[1].public_key.x == 0x2601ded51b3d232bb40791f4761b34da7170c680dc1f27d87a8970320de932f8);
    assert(public_keys[1].public_key.y == 0x1e67325076cea0b9af317ff09627610d24ef943cce4da5dcf1c15b126b04911f);

    assert(criteria.conditions[0].attr_code == 0x62697274685f646179);
    assert(criteria.conditions[0].operator == 2);
    assert(criteria.conditions[0].value == 10);
    assert(criteria.conditions[0].issuer_codes[0] == 0x6973737565723030);

    assert(criteria.conditions[1].attr_code == 0x62697274685f646179);
    assert(criteria.conditions[1].operator == 2);
    assert(criteria.conditions[1].value == 10);
    assert(criteria.conditions[1].issuer_codes[0] == 0x6973737565723031);

    assert(criteria.predicates == [0, 2, 3]);

    assert(credentials[0].subject_code == 0x6b656e);
    assert(credentials[0].expired_date == 5);
    assert(credentials[0].issuer_index == 0);
    assert(credentials[0].claims[0].code == 0x62697274685f646179);
    assert(credentials[0].claims[0].value == 19);
    // assert(credentials[0].signature.s == 0x5762c39ecb736513839365406c877a66783ad54a10bc81206ab5c9a8476d881);
    assert(credentials[0].signature.r8.x == 0x27f3c693edd9b0d40b41c8968b02a36bf79ac98421403b0b7048c6ac87e467d3);
    // assert(credentials[0].signature.r8.y == 0xef455e9fce2452dcbff7b3bc0441d774efa4e3f31f7bc084402771b1da4bed1);
    assert(credentials[0].non_revocation_proof.siblings[0] == 0);
    assert(credentials[0].non_revocation_proof.old_item == 0);
    assert(credentials[0].non_revocation_proof.is_old_0 == 1);

    assert(credentials[1].subject_code == 0x6b656e);
    assert(credentials[1].expired_date == 5);
    assert(credentials[1].issuer_index == 1);
    assert(credentials[1].claims[0].code == 0x62697274685f646179);
    assert(credentials[1].claims[0].value == 19);
    // assert(credentials[1].signature.s == 0x4d1eee6fe18e864064b8170f5cbf1959404f70428970c229191968c4ef82ffd);
    // assert(credentials[1].signature.r8.x == 0xe3910799bade0b1400801e778f787309e7a3c17b211ebb76272dd0669d63201);
    assert(credentials[1].signature.r8.y == 0x16757ffdd6413eee650b1881d7ed8669aadf06d81b0aa919e1e043a4da972ace);
    assert(credentials[1].non_revocation_proof.siblings[0] == 0);
    assert(credentials[1].non_revocation_proof.old_item == 0);
    assert(credentials[1].non_revocation_proof.is_old_0 == 1);
}


fn main(
    criteria: pub AccessControlCriteria<MAX_CONDITIONS,MAX_CONDITION_ISSUERS,MAX_PREDICATES>,
    credentials: [Credential<MAX_CLAIMS,MAX_SIBLINGS>; MAX_CREDENTIALS],
    public_keys: pub [Issuer; MAX_ISSUERS],
    proving_time: pub u8,
    revocation_roots: pub [Field; MAX_CREDENTIALS]
) {
    // test(criteria, credentials, public_keys, proving_time, revocation_roots);
    let condition_validations = validate_conditions(
        criteria.conditions,
        credentials,
        public_keys,
        proving_time,
        revocation_roots
    );

    let verification = validate_predicates(criteria.predicates, condition_validations);

    assert(verification == true);
}