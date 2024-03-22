use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use num_traits::Num;
// use ark_ff::PrimeField;
// use ark_ff::Zero;
use noir_rs::{
    native_types::{Witness, WitnessMap},
    FieldElement,
};
use serde_derive::Deserialize;
use serde_json::Value;
use std::{env, io::Write};
use std::fs;
use std::path::Path;
use toml;
use std::io;


#[derive(Deserialize, Debug)]
struct Condition {
    attr_code: String,
    operator: u8,
    value: u8,
    issuer_codes: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct AccessControlCriteria {
    predicates: Vec<u8>,
    conditions: Vec<Condition>,
}

#[derive(Deserialize, Debug)]
struct Claim {
    code: String,
    value: u8,
}

#[derive(Deserialize, Debug)]
struct Point {
    x: String,
    y: String,
}

type PublicKey = Point;

#[derive(Deserialize, Debug)]
struct Signature {
    s: String,
    r8: Point,
}

#[derive(Deserialize, Debug)]
struct ExclusionMerkleTreeProof {
    siblings: Vec<String>,
    old_item: String,
    is_old_0: u8,
}

#[derive(Deserialize, Debug)]
struct Credential {
    subject_code: String,
    claims: Vec<Claim>,
    expired_date: u8,
    signature: Signature,
    non_revocation_proof: ExclusionMerkleTreeProof,
    issuer_index: u8,
}

#[derive(Deserialize, Debug)]
struct Issuer {
    issuer_code: String,
    public_key: PublicKey,
}

#[derive(Deserialize, Debug)]
struct Input {
    proving_time: u8,
    revocation_roots: Vec<String>,
    criteria: AccessControlCriteria,
    credentials: Vec<Credential>,
    public_keys: Vec<Issuer>,
}

fn convert_hex_to_field_element(hex_str: &str) -> Option<FieldElement> {
    if hex_str == "0x0" {
        Some(FieldElement::from(0_i128))
    } else {
        let new_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bigint = BigUint::from_str_radix(new_str, 16).unwrap();

        Some(FieldElement::from_be_bytes_reduce(&bigint.to_bytes_be()))
    }
}

fn convert_uint_to_field_element(number: u8) -> FieldElement {
    FieldElement::from(number as u128)
}

fn get_circuit_directory(circuit_name: &str) -> Option<String> {
    match circuit_name {
        "vcp_generation" | "mono_vcp_generation" => {
            let path = Path::new("..").join("circuits").join(circuit_name);
            // println!("{:?}", &path);

            return Some(String::from(path.to_str().unwrap()));
        },

        _ => {
            println!("Invalid circuit name: {:?}", circuit_name);
            None
        }
    }
}

fn load_compiled_artifact(circuit_directory: &str, circuit_name: &str) -> Value {
    // let circuit_directory = get_circuit_directory(circuit_name).unwrap();
    let artifact_path = Path::new(&circuit_directory).join("target").join(format!("{}.json", circuit_name));
    let data =
        fs::read_to_string(artifact_path).expect("Unable to read file");
    let json: Value = serde_json::from_str(&data).expect("Unable to parse JSON");

    json
}

fn load_input_file(circuit_directory: &str) -> Option<Input> {
    // let circuit_directory = get_circuit_directory(circuit_name).unwrap();
    let input_path = Path::new(&circuit_directory).join("Prover.toml");
    let data_str = fs::read_to_string(input_path).expect("Unable to read Prover.toml");

    Some(toml::from_str(&data_str).expect("Unable to parse TOML"))
}

fn build_witness(input: Input, compiled_program: &Value) -> WitnessMap {
    let mut initial_witness = WitnessMap::new();
    // initial_witness.insert(Witness(1), FieldElement::from(0_i128));
    // let mut min_index = 1000000;
    // let mut max_index = -1;

    let param_witnesses = compiled_program["abi"]["param_witnesses"]
        .as_object()
        .unwrap();
    // println!("{:?}", param_witnesses);

    for (key, value) in param_witnesses.into_iter() {
        // println!("{:?} - {:?}", key, value);

        let temp = value.as_array().unwrap();
        // println!("{:?}", temp);

        if key == "proving_time" {
            let start_index = temp[0]["start"].as_u64().unwrap();
            initial_witness.insert(
                Witness(start_index as u32),
                convert_uint_to_field_element(input.proving_time),
            );
        } else if key == "revocation_roots" {
            let start_index = temp[0]["start"].as_u64().unwrap() as usize;

            for index in 0..input.revocation_roots.len() {
                let adding_index: u32 = (start_index + index) as u32;

                initial_witness.insert(
                    Witness(adding_index),
                    convert_hex_to_field_element(&input.revocation_roots[index])
                        .expect("Cannot convert revocation root"),
                );
            }
        } else if key == "public_keys" {
            let start_index = temp[0]["start"].as_u64().unwrap() as usize;

            for index in 0..input.public_keys.len() {
                let adding_index: u32 = (start_index + index * 3) as u32;

                initial_witness.insert(
                    Witness(adding_index),
                    convert_hex_to_field_element(&input.public_keys[index].issuer_code)
                        .expect("Cannot convert issuer_code"),
                );
                initial_witness.insert(
                    Witness(adding_index + 1),
                    convert_hex_to_field_element(&input.public_keys[index].public_key.x)
                        .expect("Cannot convert public key"),
                );
                initial_witness.insert(
                    Witness(adding_index + 2),
                    convert_hex_to_field_element(&input.public_keys[index].public_key.y)
                        .expect("Cannot convert public key"),
                );
            }
        } else if key == "criteria" {
            let start_index = temp[0]["start"].as_u64().unwrap() as usize;

            for index in 0..input.criteria.conditions.len() {
                let adding_index: u32 = (start_index + index * 4) as u32;
                let condition = &input.criteria.conditions[index];

                initial_witness.insert(
                    Witness(adding_index),
                    convert_hex_to_field_element(&condition.attr_code)
                        .expect("Cannot convert attr_code"),
                );
                initial_witness.insert(
                    Witness(adding_index + 1),
                    convert_uint_to_field_element(condition.operator),
                );
                initial_witness.insert(
                    Witness(adding_index + 2),
                    convert_uint_to_field_element(condition.value),
                );

                for j in 0..condition.issuer_codes.len() {
                    initial_witness.insert(
                        Witness(adding_index + 3 + j as u32),
                        convert_hex_to_field_element(&condition.issuer_codes[j])
                            .expect("Cannot convert condition issuer_code"),
                    );
                }
            }

            for index in 0..input.criteria.predicates.len() {
                let adding_index: u32 =
                    (start_index + input.criteria.conditions.len() * 4 + index) as u32;
                let predicate = input.criteria.predicates[index];
                initial_witness.insert(
                    Witness(adding_index),
                    convert_uint_to_field_element(predicate),
                );
            }
        } else if key == "credentials" {
            let credentials = &input.credentials;
            let mut current_index = temp[0]["start"].as_u64().unwrap() as u32;

            for index in 0..credentials.len() {
                let credential = &credentials[index];
                let num_claims = credential.claims.len() as u32;
                let num_siblings = credential.non_revocation_proof.siblings.len();

                let subject_index = current_index;
                let claim_start_index = subject_index + 1;
                let expired_date_index = claim_start_index + num_claims * 2;
                let signature_index = expired_date_index + 1;
                let non_revocation_proof_index = signature_index + 3;
                let issuer_index = non_revocation_proof_index + 34;

                initial_witness.insert(
                    Witness(subject_index),
                    convert_hex_to_field_element(&credential.subject_code)
                        .expect("Cannot convert credential subject_code"),
                );

                for j in 0..num_claims {
                    let claim = &credential.claims[j as usize];
                    let claim_index = (claim_start_index + j * 2) as u32;

                    initial_witness.insert(
                        Witness(claim_index),
                        convert_hex_to_field_element(&claim.code)
                            .expect("Cannot convert claim code"),
                    );
                    initial_witness.insert(
                        Witness(claim_index + 1),
                        convert_uint_to_field_element(claim.value),
                    );
                }

                initial_witness.insert(
                    Witness(expired_date_index),
                    convert_uint_to_field_element(credential.expired_date),
                );

                initial_witness.insert(
                    Witness(signature_index),
                    convert_hex_to_field_element(&credential.signature.s)
                        .expect("Cannot convert signature s"),
                );
                initial_witness.insert(
                    Witness(signature_index + 1),
                    convert_hex_to_field_element(&credential.signature.r8.x)
                        .expect("Cannot convert signature r8.x"),
                );
                initial_witness.insert(
                    Witness(signature_index + 2),
                    convert_hex_to_field_element(&credential.signature.r8.y)
                        .expect("Cannot convert signature r8.y"),
                );

                let non_revocation_proof = &credential.non_revocation_proof;
                for j in 0..num_siblings {
                    let sibling = &non_revocation_proof.siblings[j];

                    initial_witness.insert(
                        Witness(non_revocation_proof_index + j as u32),
                        convert_hex_to_field_element(&sibling).expect("Cannot convert sibling"),
                    );
                }

                initial_witness.insert(
                    Witness(non_revocation_proof_index + num_siblings as u32),
                    convert_hex_to_field_element(&non_revocation_proof.old_item)
                        .expect("Cannot convert proof old item"),
                );

                initial_witness.insert(
                    Witness(non_revocation_proof_index + num_siblings as u32 + 1),
                    convert_uint_to_field_element(non_revocation_proof.is_old_0),
                );

                initial_witness.insert(
                    Witness(issuer_index),
                    convert_uint_to_field_element(credential.issuer_index),
                );

                current_index = current_index + 6 + 34 + 2 * num_claims;
            }
        }
    }
    // for data in compiledProgram["abi"]["param_witnesses"] {
    //     println!("{}", data);
    // }

    initial_witness
}

fn write_data(directory: &str, file_name: &str, data: Vec<u8>) -> Result<(), std::io::Error> {
    let path = Path::new(directory).join(file_name);
    let binding = path.to_str().unwrap();

    fs::write(binding, data)?;

    Ok(())
}


fn read_data(directory: &str, file_name: &str) -> Result<Vec<u8>, std::io::Error> {
    let path = Path::new(directory).join(file_name);
    let binding = path.to_str().unwrap();

    let data = fs::read(&binding)?;

    Ok(data)
}

fn save_proof_and_vk(circuit_directory: &str, proof: Vec<u8>, vk: Vec<u8>) -> Result<(), String> {
    let proofs_directory = Path::new(&circuit_directory).join("proofs");
    let binding = proofs_directory.to_str().unwrap();

    write_data(&binding, "myproof.proof", proof).expect("Cannot write proof file");
    write_data(&binding, "myvk.vk", vk).expect("Cannot write vk file");

    Ok(())
}


fn read_proof_and_vk(circuit_directory: &str) -> Result<(Vec<u8>,Vec<u8>), String> {
    let proofs_directory = Path::new(&circuit_directory).join("proofs");
    let binding = proofs_directory.to_str().unwrap();

    let proof = read_data(&binding, "myproof.proof").expect("Cannot read proof file");
    let vk = read_data(&binding, "myvk.vk").expect("Cannot read vk file");

    Ok((proof, vk))
}

#[derive(Parser, Debug)]
#[clap(version, about)]
struct Args {
    #[arg(short, long)]
    circuit: String,

    #[arg(short, long)]
    mode: String,
}

fn main() {
    let args = Args::parse();
    println!("{:?}", &args);
    let circuit_name = args.circuit;
    let mode = args.mode.as_str();

    let circuit_directory = get_circuit_directory(&circuit_name).unwrap();
    let compiled_artifact = load_compiled_artifact(&circuit_directory, &circuit_name);
    let bytecode: &str = compiled_artifact["bytecode"]
        .as_str()
        .expect("Unable to extract bytecode");

    match mode {
        "prove" => {
            println!("Loading Prover.toml...");
            let input_data = load_input_file(&circuit_directory).expect("Cannot parse input data");
            println!("Initializing witness...");
            let initial_witness = build_witness(input_data, &compiled_artifact);

            println!("Generating proof...");
            let (proof, vk) = noir_rs::prove(String::from(bytecode), initial_witness).unwrap();
            // println!("proof={:?}", proof);
            // println!("vk={:?}", vk);
            // save proof and vk
            let _ = save_proof_and_vk(&circuit_directory, proof, vk);
        },
        "verify" => {
            println!("Verifying proof...");
            let (proof1, vk1) = read_proof_and_vk(&circuit_directory).expect("Cannot read proof and vk");
            // println!("proof={:?}", proof1);
            // println!("vk={:?}", vk1);
            // read proof & vk
            let verdict = noir_rs::verify(String::from(bytecode), proof1, vk1).unwrap();
            assert!(verdict);
            println!("Proof correct");

        },
        _ => println!("Invalid mode: {:?}", mode),
    }
}
