import { createSMT as createSparseMerkleTree } from "./circom_smt_utils";
import { bigIntToHex, bytesToHex } from "@nomicfoundation/ethereumjs-util";

import { Claim, Condition, Issuer, Credential, ConditionNode, MerkleTreeProof, UnifiedCredential, Criteria } from "./data";
import { SMT } from "circomlibjs";

export enum zkVCMode {
    SingleProof = 0,
    MultiProof,
}

async function generateEmptyNonRevocationTrees(numIssuers: number): Promise<Map<string, SMT>> {
    let issuerRevocationTrees = new Map<string, SMT>();

    for (let i = 0; i < numIssuers; i++) {
        issuerRevocationTrees.set(`issuer0${i}`, await createSparseMerkleTree());
    }

    return issuerRevocationTrees;
}

async function generateRoots(credentials: Credential[], issuerRevocationTrees: Map<string, SMT>) {
    let roots = [];
    for (let credential of credentials) {
        const nonRevocationTree = issuerRevocationTrees.get(credential.issuer.name)!;

        const hash = credential.updateHash();

        const proof = await MerkleTreeProof.generateExclusionProof(nonRevocationTree, hash);
        credential.nonRevocationProof = proof;
        const root = nonRevocationTree.F.toObject(nonRevocationTree.root);
        roots.push(bigIntToHex(root));
    }

    return roots;
}

function generateVCs(numCredentials: number) {
    const privateKey = "secret";
    let credentials: Credential[] = [];

    for (let i = 0; i < numCredentials; i++) {
        credentials.push(new Credential(
            new Issuer(`issuer0${i}`, privateKey),
            "ken",
            5,
            [
                new Claim("birth_day", 19)
            ],
            privateKey)
        );
    }

    return credentials;
}


function getConditionsAndVCs(numConditions: number) {
    let conditions: ConditionNode;
    let credentials: Credential[] = generateVCs(numConditions);

    const conditionsMap2: Record<number, ConditionNode> = {
        1: {
            value: new Condition("birth_day", ">", 10, ["issuer00"])
        },
        2: {
            value: "&",
            left: {
                value: new Condition("birth_day", ">", 10, ["issuer00"]),
            },
            right: {
                value: new Condition("birth_day", ">", 10, ["issuer01"]),
            }
        },
        3: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer00"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer01"]),
                }
            },
            right: {
                value: new Condition("birth_day", ">", 10, ["issuer02"]),
            }
        },
        4: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer00"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer01"]),
                }
            },
            right: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer02"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer03"]),
                }
            }
        },
        5: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer00"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer01"])
                    }
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer02"]),
                }
            },
            right: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer03"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer04"]),
                }
            }
        },
        6: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer00"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer01"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer02"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer03"])
                    }
                }
            },
            right: {
                value: "|",
                left: {
                    value: new Condition("birth_day", ">", 10, ["issuer04"]),
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer05"]),
                }
            }
        },
        7: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer00"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer01"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer02"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer03"])
                    }
                }
            },
            right: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer04"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer05"])
                    }
                },
                right: {
                    value: new Condition("birth_day", ">", 10, ["issuer06"]),
                }
            }
        },
        8: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer00"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer01"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer02"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer03"])
                    }
                }
            },
            right: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer04"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer05"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer06"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer07"])
                    }
                }
            }
        },
        9: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: "&",
                        left: {
                            value: new Condition("birth_day", ">", 10, ["issuer00"])
                        },
                        right: {
                            value: new Condition("birth_day", ">", 10, ["issuer01"])
                        }
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer02"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer03"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer04"])
                    }
                }
            },
            right: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer05"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer06"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer07"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer08"])
                    }
                }
            }
        },
        10: {
            value: "&",
            left: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: "&",
                        left: {
                            value: new Condition("birth_day", ">", 10, ["issuer00"])
                        },
                        right: {
                            value: new Condition("birth_day", ">", 10, ["issuer01"])
                        }
                    },
                    right: {
                        value: "&",
                        left: {
                            value: new Condition("birth_day", ">", 10, ["issuer02"])
                        },
                        right: {
                            value: new Condition("birth_day", ">", 10, ["issuer03"])
                        }
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer04"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer05"])
                    }
                }
            },
            right: {
                value: "|",
                left: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer06"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer07"])
                    }
                },
                right: {
                    value: "&",
                    left: {
                        value: new Condition("birth_day", ">", 10, ["issuer08"])
                    },
                    right: {
                        value: new Condition("birth_day", ">", 10, ["issuer09"])
                    }
                }
            }
        }
    }

    if (numConditions in conditionsMap2) {
        conditions = conditionsMap2[numConditions];
        // console.log(conditions);
    } else {
        throw new Error(`Unsupported test setting number of conditions: ${numConditions}`);
    }

    return { conditions, credentials };
}

export async function generateTestInputs(numIssuers: number, numSiblings: number) {
    MerkleTreeProof.maxSiblings = numSiblings;

    const { conditions, credentials } = getConditionsAndVCs(numIssuers);

    let issuerRevocationTrees = await generateEmptyNonRevocationTrees(numIssuers);
    let roots = await generateRoots(credentials, issuerRevocationTrees);

    const unifiedCredential = new UnifiedCredential(credentials);
    const criteria = new Criteria(
        conditions
    );

    const { credentials: serializedCredentials, issuers } = unifiedCredential.serializeNoir();

    return {
        criteria: criteria.serializeNoir(),
        credentials: serializedCredentials,
        public_keys: issuers,
        proving_time: 0,
        revocation_roots: roots,
    }
}