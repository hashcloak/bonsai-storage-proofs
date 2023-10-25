pragma solidity ^0.8.17;

import {IBonsaiRelay} from "bonsai/IBonsaiRelay.sol";
import {BonsaiCallbackReceiver} from "bonsai/BonsaiCallbackReceiver.sol";

contract StorageProofChecker is BonsaiCallbackReceiver {
    mapping(uint256 => uint256) public resultCache;

    /// @notice Image ID of the only zkVM binary to accept callbacks from.
    bytes32 public immutable storImageId;

    /// @notice Gas limit set on the callback from Bonsai.
    /// @dev Should be set to the maximum amount of gas your callback might reasonably consume.
    uint64 private constant BONSAI_CALLBACK_GAS_LIMIT = 100000;

    /// @notice Initialize the contract, binding it to a specified Bonsai relay and RISC Zero guest image.
    constructor(IBonsaiRelay bonsaiRelay, bytes32 _storImageId) BonsaiCallbackReceiver(bonsaiRelay) {
        storImageId = _storImageId;
    }

    function storeResult(uint256 id, uint256 result) external onlyBonsaiCallback(storImageId) {
        // For testing purposes, we use an id mapping structure to retrieve result
        resultCache[id] = result;
    }

    function verifyStorageProof(uint256 id, string calldata data) external {
        // id is passed for testing purposes
        bonsaiRelay.requestCallback(
            storImageId, abi.encode(id, data), address(this), this.storeResult.selector, BONSAI_CALLBACK_GAS_LIMIT
        );
    }

    function retrieveResult(uint256 id) external view returns (uint256) {
        uint256 result = resultCache[id];
        // 0 is the default value
        require(result != 0, "value not available in cache");
        return result;
    }

}
