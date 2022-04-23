// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract GpgEncryption {
    ///@notice this struct defines what the details in an encrypted message
    /// @param sender - the sender of the encrypted messaged
    /// @param recipient - the recipient of the message
    struct encryptedMessage {
        address sender;
        address recipient;
        string messageURL;
    }

    /// @notice Emitted when message is encrypted
    /// @param sender is encrypter of message
    /// @param messageId is id of message encrypted
    event MessageEncrypted(
        address sender,
        address recipient,
        uint256 messageId
    );

    /// @notice maps user address to thier gpg public key(already hashed)
    mapping(address => bytes32) private userPublicGpgKeys;

    /// @notice maps user address to an array of encrypted messages
    /// @dev each encrypted message is of type of struct encryptedMessage above
    mapping(address => encryptedMessage[]) private userEncryptedMessages;

    /// @notice maps user address to bool value when they assign/store thier gpg private keys
    mapping(address => bool) public hasAssignedPublicKeys;

    /// @notice a counter to keep track of all messages encrypted- will help to give Id tp each encrypted message
    uint256 private numOfEncryptedMsg;

    /// @notice maps an id to an encrypted message
    mapping(uint256 => encryptedMessage) private idToEncryptedMessage;

    /// @notice allows an address to set/assign its gpg private key
    /// @param _key is the gpg private key

    function setPublicKey(bytes32 _key) public {
        hasAssignedPublicKeys[msg.sender] = true;
        userPublicGpgKeys[msg.sender] = _key;
    }

    /// @notice allows a user to encrypt message for another user
    /// @param _messageURL is url/hash/pointer to the file/message
    /// @param _recipient is address of the recipient
    function encryptMessageForAddress(
        string memory _messageURL,
        address _recipient
    ) public {
        require(
            userPublicGpgKeys[msg.sender].length != 0,
            "You need to first assign your gpg public key to your address, this key will be requested by recipient to validate its the actual recipient of the message"
        );

        uint256 _messageId = numOfEncryptedMsg + 1;
        encryptedMessage memory _encryptedMessage = encryptedMessage({
            sender: msg.sender,
            recipient: _recipient,
            messageURL: _messageURL
        });

        numOfEncryptedMsg = _messageId;
        userEncryptedMessages[msg.sender].push(_encryptedMessage);
        idToEncryptedMessage[_messageId] = _encryptedMessage;

        emit MessageEncrypted(msg.sender, _recipient, _messageId);
    }

    /// @notice allows a recipient to decrypt a message
    /// @param _messageId is the id of the message
    /// @param _senderPublicKey is the key of the sender that verifies that the address attempting to decrypt is the actual recipient
    /// @return returns the message url once the sender public key and recipient is verified
    function decryptMessage(bytes32 _senderPublicKey, uint256 _messageId)
        public
        view
        returns (string memory)
    {
        //firstly check if the caller of the function is the recipient of the message
        // and if the provided address of _sender is the sender of the message with this id
        require(
            idToEncryptedMessage[_messageId].recipient == msg.sender,
            "check that you are the recipient of the message with this"
        );
        require(
            userPublicGpgKeys[idToEncryptedMessage[_messageId].sender] ==
                _senderPublicKey,
            "you dont have the correct key to decrpyt this message, contact the sender"
        );

        return idToEncryptedMessage[_messageId].messageURL;
    }
}
