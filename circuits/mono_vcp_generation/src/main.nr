use dep::std::hash::poseidon;
use dep::std::eddsa::eddsa_poseidon_verify;
use dep::smt;
use dep::zkvc::{AccessControlCriteria, UnifiedCredential, Condition, Credential, Issuer, validate_conditions, validate_predicates};
use dep::settings::{MAX_CLAIMS,MAX_CONDITION_ISSUERS,MAX_SIBLINGS,MAX_CONDITIONS,MAX_CREDENTIALS,MAX_ISSUERS,MAX_PREDICATES};


fn main(
    criteria: pub AccessControlCriteria<MAX_CONDITIONS,MAX_CONDITION_ISSUERS,MAX_PREDICATES>,
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
