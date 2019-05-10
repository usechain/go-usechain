pragma solidity ^0.4.20;

contract Committee {
    /// @notice Whether the msg.sender is committee or not.
    /// @return Whether the transfer was successful or not
    function IsOndutyCommittee(address _user) public view returns(bool);
}

contract CreditSystem {
    uint public unConfirmedMainAddressLen = 0;
    uint public unConfirmedSubAddressLen  = 0;
    uint public unEncryptedSubAddressLen = 0;
    uint public confirmedMainAddressLen = 0;
    uint public confirmedSubAddressLen = 0;
    uint public RegisterID = 1;

    /// @notice Committee contract address
    address public CommitteeAddr = address(0xffFFFfFFffFfffffFffFFfFFFFFFFFFff0000003);

    struct mainAccount {
        address         addr;           // msg.sender
        bytes32         hashKey;        // keccak(idtype + idnum)
        uint            status;         // verified status, 0 means unregister, 1 means unreviewed, 2 means verifying , 3 means Approved, 4 means rejected
        bytes           identity;       // certificate's data
        bytes           issuer;         // certificate's issuer
        string          publicKey;      // user's publicKey
    }

    struct subAccount {
        address         addr;
        uint            status;                 // sub account verify state
        string          publicKey;              // sub account's public key
        string          encryptedAS;            // sub account's encrypted AS publicKey
    }

    mapping (address => subAccount) public SubAccount;
    mapping (address => mainAccount) public MainAccount;

    address[] public confirmedMainAddress;  // Reserved data is used to query the number of confirmed MainAddress
    address[] public confirmedSubAddress;   // Reserved data is used to query the number of confirmed SubAddress
    uint[] public UnEncryptedSubAddrID;     // UnEncryptedSubAddress's registerID, unEncryptedSubAddress means unConfirmedSubAddress use plain text
    uint[] public UnConfirmedSubAddrID;     // UnConfirmedSubAddress's registerID
    uint[] public UnConfirmedMainAddrID;    // UnConfirmedMainAddress's registerID

    struct registeredAddr {               // store registered address
        bool verified;
        address toAddress;
    }

    mapping (uint => registeredAddr) public RegisterIDtoAddr;


    /// @notice only committee can do
    modifier onlyCommittee(address _user) {
        require (Committee(CommitteeAddr).IsOndutyCommittee(_user) == true);
        _;
    }

    function test(address _user) public view returns(bool){
        return Committee(CommitteeAddr).IsOndutyCommittee(_user) == true;
    }

    modifier MainAccountUnVerifying(address _addr) {
        require (MainAccount[_addr].status != 1); // verifying status cannot register, unregistered or rejected can register, verified can update info.
        _;
    }

    modifier SubAccountUnVerifying(address _addr) {
        require (SubAccount[_addr].status != 1); // same annotation as above
        _;
    }

    modifier UnVerifiedRegisterID(uint _registerID) {
        require(!RegisterIDtoAddr[_registerID].verified);
        _;
    }

    // main account register
    function register(string memory _publicKey,
                    bytes32 _hashKey,
                    bytes memory _identity,
                    bytes memory _issuer,
                    bool _ciphertext)
        MainAccountUnVerifying(msg.sender)
        public
        payable
        returns(bool){
        MainAccount[msg.sender].addr = msg.sender;
        MainAccount[msg.sender].publicKey = _publicKey;
        MainAccount[msg.sender].hashKey = _hashKey;
        MainAccount[msg.sender].identity = _identity;
        MainAccount[msg.sender].issuer = _issuer;
        uint _registerID = RegisterID;
        RegisterIDtoAddr[_registerID].toAddress = msg.sender;
        RegisterID += 1;
        if (_ciphertext == true) {
                MainAccount[msg.sender].status = 3;
                RegisterIDtoAddr[_registerID].verified = true;
                confirmedMainAddress.push(msg.sender);
                confirmedMainAddressLen = confirmedMainAddress.length;
               return true;
        }
        MainAccount[msg.sender].status = 1;
        UnConfirmedMainAddrID.push(_registerID);
        unConfirmedMainAddressLen = UnConfirmedMainAddrID.length;
        return true;
    }

    // sub account register
   function subRegister(string _pubkey, string _encryptedAS, bool _ciphertext)
        SubAccountUnVerifying(msg.sender)
        public
        payable
        returns(bool)
    {
        uint _registerID = RegisterID;
        SubAccount[msg.sender].addr = msg.sender;
        SubAccount[msg.sender].publicKey = _pubkey;
        SubAccount[msg.sender].encryptedAS = _encryptedAS;
        RegisterIDtoAddr[_registerID].toAddress = msg.sender;
        RegisterID += 1;
        SubAccount[msg.sender].status = 1;
        if (_ciphertext == true) {
               UnEncryptedSubAddrID.push(_registerID);
               unEncryptedSubAddressLen = UnEncryptedSubAddrID.length;
               return true;
        }
        UnConfirmedSubAddrID.push(_registerID);
        unConfirmedSubAddressLen = UnConfirmedSubAddrID.length;
        return true;
    }

    // @dev check that Account status, when one account register sub and main at the same time,
    // return main account status
    function getAccountStatus(address _addr) public view returns (uint) {
        if (MainAccount[_addr].status != 0) {
            return MainAccount[_addr].status;
        }
        if (SubAccount[_addr].status != 0) {
            return SubAccount[_addr].status;
        }
        return 0;
    }

    function getUnConfirmedMainAddrLen()
        public
        view
        returns(uint){
        return UnConfirmedMainAddrID.length;
    }

    function getUnConfirmedSubAddrLen()
        public
        view
        returns(uint){
        return UnConfirmedSubAddrID.length;
    }

    function getUnEncryptedSubAddrLen()
        public
        view
        returns(uint){
        return UnEncryptedSubAddrID.length;
    }

    function verifyHash(uint _registerID, bytes32 _hash, uint _status, address _verifiedAddr)
        public
        onlyCommittee(msg.sender)
        UnVerifiedRegisterID(_registerID)
        returns(bool){
            address _addr = RegisterIDtoAddr[_registerID].toAddress;
            require(_verifiedAddr == _addr);
            require(MainAccount[_addr].addr != address(0));
            require(MainAccount[_addr].status == 1);
            require(MainAccount[_addr].hashKey == _hash);
            if (SubAccount[_addr].status != 0 ) { // sub account can't verified as main account
                _status = 0;    // adjust mainAccount to unregister status in order to getAccountStatus() can return correct value
            }
            MainAccount[_addr].status = _status;
            if (_status == 3) {
                RegisterIDtoAddr[_registerID].verified = true;
                confirmedMainAddress.push(_addr);
                confirmedMainAddressLen = confirmedMainAddress.length;
            }
            for (uint i= 0; i < unConfirmedMainAddressLen; i++) {
                if (UnConfirmedMainAddrID[i] == _registerID) {
                    UnConfirmedMainAddrID[i] = UnConfirmedMainAddrID[unConfirmedMainAddressLen - 1];
                    UnConfirmedMainAddrID.length -= 1;
                    unConfirmedMainAddressLen = UnConfirmedMainAddrID.length;
                }
            }
        return true;
    }

    function verifySub(uint _registerID, uint _status)
        public
        onlyCommittee(msg.sender)
        UnVerifiedRegisterID(_registerID)
        returns(bool){
            require(_registerID != 0);
            address _addr = RegisterIDtoAddr[_registerID].toAddress;
            require(SubAccount[_addr].addr != address(0));
            require(SubAccount[_addr].status == 1);
            if (MainAccount[_addr].status != 0 ) { // main account can't verified as sub account
                _status = 0;  // adjust subAccount to unregister status in order to getAccountStatus() can return correct value
            }
            SubAccount[_addr].status = _status;
            if (_status == 3) {
                RegisterIDtoAddr[_registerID].verified = true;
                confirmedSubAddress.push(_addr);
                confirmedSubAddressLen = confirmedSubAddress.length;
            }
            for (uint i= 0; i < unConfirmedSubAddressLen; i++) {
                if (UnConfirmedSubAddrID[i] == _registerID) {
                    UnConfirmedSubAddrID[i] = UnConfirmedSubAddrID[unConfirmedSubAddressLen - 1];
                    UnConfirmedSubAddrID.length -= 1;
                    unConfirmedSubAddressLen = UnConfirmedSubAddrID.length;
                }
            }
        return true;
    }
}
