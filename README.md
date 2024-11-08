# zkSSI: The Zero-Knowledge Multiple-Condition Self-Sovereign Identity Framework
This project illustrates the implementation of the zkSSI framework. zkSSI allows on-chain and off-chain verifiers to specify attribute-based access control policies. Holders can obtain verifiable credentials from issuers. Then, the holders can generate the zero-knowledge verifiable presentation of their credentials to prove that their credentials satisfy verifiers' policies.

zkSSI includes three main components:
- Verifiation presentation generation: uses zk-snarks (i.e., Noir) to generate the presentation.
- Presentation verification: allows on-chain and off-chain verifiers to verify the presentation.

# Citation
If this project is interesting to your work, please cite it as follows:
```
@INPROCEEDINGS{10664246,
  author={Hoang, Anh-Tu and Ileri, Can Umut and Sanders, William and Schulte, Stefan},
  booktitle={2024 IEEE International Conference on Blockchain (Blockchain)}, 
  title={zkSSI: A Zero-Knowledge-Based Self-Sovereign Identity Framework}, 
  year={2024},
  pages={276-285},
  doi={10.1109/Blockchain62396.2024.00043}}
```
