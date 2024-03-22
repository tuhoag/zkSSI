use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;
use dep::zkvc::{AccessControlCriteria, UnifiedCredential, Condition, Credential, Issuer, validate_conditions, validate_predicates};


global MAX_CLAIMS = 1;


// 1 CONDITION
global MAX_CONDITIONS = 1;
global MAX_PREDICATES = 1;
global MAX_CREDENTIALS = 1;
global MAX_ISSUERS = 1;

// 2 CONDITIONS
// global MAX_CONDITIONS = 2;
// global MAX_PREDICATES = 3;
// global MAX_CREDENTIALS = 2;
// global MAX_ISSUERS = 2;

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
// global MAX_CONDITIONS = 1;
// global MAX_CREDENTIALS = 1;
// global MAX_ISSUERS = 1;
// global MAX_PREDICATES = 3;

global MAX_SIBLINGS = 32;

fn main(
    criteria: AccessControlCriteria<MAX_CONDITIONS,MAX_ISSUERS,MAX_PREDICATES>,
    credentials: [Credential<MAX_CLAIMS,MAX_SIBLINGS>; MAX_CREDENTIALS],
    public_keys: pub [Issuer; MAX_ISSUERS],
    proving_time: pub u8,
    revocation_roots: pub [Field; MAX_CREDENTIALS]
) {
    let condition_validations = validate_conditions(
        criteria.conditions,
        credentials,
        public_keys,
        proving_time,
        revocation_roots
    );

    for i in 0..MAX_CONDITIONS {
        assert(condition_validations[i] == true);

    }
}
