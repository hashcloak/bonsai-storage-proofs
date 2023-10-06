# Verifying Storage Proofs using Bonsai

Verify a storage proof as described in [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186) using Bonsai. 

Send a single storage proof as a json string to the `StorageProofChecker` smart contract. Using Bonsai, the storage value based on the storage proof is returned and stored in the contract. 
This can then be retrieved and compared to expected value.

## Build and test

After cloning obtain all necessary libraries in `lib`, as they are in the [Starter template](https://github.com/risc0/bonsai-foundry-template/tree/main/lib). TODO: correctly add submodules

Build:
```
cargo build
cargo test
```

Run test in `StorageProofChecker.t.sol`:
```
forge test
```

This test does 2 storageProof verifications. The testdata for them were obtained from the Optimism Goerli network using web3. See more information in `tests/TEST_INFO.md` on how to obtain testdata and use this for additional testing.

## Resources

Used resources:
- [EIP-1186](https://eips.ethereum.org/EIPS/eip-1186)
- Example implementation (archived) https://github.com/ComposableFi/patricia-merkle-trie/tree/main
- [bonsai-foundry-starter](https://github.com/risc0/bonsai-foundry-template)