pragma solidity ^0.4.20;

//import "https://github.com/OpenZeppelin/openzeppelin-solidity/contracts/access/roles/SignerRole.sol";

/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev give an account access to this role
     */
    function add(Role storage role, address account) internal {
        require(account != address(0));
        require(!has(role, account));

        role.bearer[account] = true;
    }

    /**
     * @dev remove an account's access to this role
     */
    function remove(Role storage role, address account) internal {
        require(account != address(0));
        require(has(role, account));

        role.bearer[account] = false;
    }

    /**
     * @dev check if an account has this role
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0));
        return role.bearer[account];
    }
}

contract SignerRole {
    using Roles for Roles.Role;

    event SignerAdded(address indexed account);
    event SignerRemoved(address indexed account);

    Roles.Role private _signers;

    function SignerRole() internal {
        _addSigner(msg.sender);
    }

    modifier onlySigner() {
        require(isSigner(msg.sender));
        _;
    }

    function isSigner(address account) public view returns (bool) {
        return _signers.has(account);
    }

    function addSigner(address account) public onlySigner {
        _addSigner(account);
    }

    function renounceSigner() public {
        _removeSigner(msg.sender);
    }

    function _addSigner(address account) internal {
        _signers.add(account);
        SignerAdded(account);
    }

    function _removeSigner(address account) internal {
        _signers.remove(account);
        SignerRemoved(account);
    }
}


contract Committee {
    /// @notice Whether the msg.sender is committee or not.
    /// @return Whether the transfer was successful or not
    function IsOndutyCommittee(address _user) public view returns(bool);
}

contract CreditSystem is SignerRole{
// contract CreditSystem is SignerRole{
    event NewUserRegister(address indexed addr, bytes32 indexed hash);
    event NewIdentity(address indexed addr, bytes32 indexed hash);

    mapping (address => UseID) IDs;
    mapping (bytes32 => UseData) DataSet;
    bytes32[] public unregister;

    /// @notice Committee contract address
    address public CommitteeAddr = address(0xffFFFfFFffFfffffFffFFfFFFFFFFFFff0000003);

    struct Hash {
        bytes32 hash;
        bool verify;
    }

    struct UseID {
        //address addr;             // msg.sender
        address useId;              // msg.sender
        string publicKey;           // user's publicKey
        Hash baseHash;              // keccak(idtype + idnum) and verified flag
        HashList hl;                // other certificate's hash and verifiy flag list implements by struct
    }

    struct UseData {
        bytes identity;             // certificate's data
        bytes issuer;               // certificate's issuer
        bool verify;                // same flag with HashList verifies
        uint index;                 // index in the unregistered array
        string publicKey;           // user's publicKey
    }

    struct HashList {
        bytes32[] hashes;           // keccak(idtype + idnum)
        bool[] verifies;            // certificate's status
    }

    /// @notice only committee can do
    modifier onlyCommittee(address _user) {
        require (Committee(CommitteeAddr).IsOndutyCommittee(_user) == true);
        _;
    }

    function test(address _user) public view returns(bool){
        return Committee(CommitteeAddr).IsOndutyCommittee(_user) == true;
    }

    function register(string memory _publicKey,
                    //address _useId,
                    bytes32 _hashKey,
                    bytes memory _identity,
                    bytes memory _issuer)
        public
        payable
        returns(bool){
        address addr = msg.sender;
        require(IDs[addr].useId == address(0)); // unregistered user
        uint index = unregister.push(_hashKey) - 1;
        UseData memory ud = UseData(_identity, _issuer, false, index, _publicKey);
        DataSet[_hashKey] = ud;
        UseID memory user = UseID(addr, _publicKey, Hash(_hashKey, false), HashList(new bytes32[](0), new bool[](0)));
        IDs[addr] = user;
        IDs[addr].hl.hashes.push(_hashKey);
        IDs[addr].hl.verifies.push(false);
        NewUserRegister(addr, _hashKey);
        return true;
    }

    function getUserInfo(address addr)
        public
        view
        returns(address, string memory, bytes32, bytes32[] memory, bool[] memory){
        return (IDs[addr].useId,
        IDs[addr].publicKey,
        IDs[addr].baseHash.hash,
        IDs[addr].hl.hashes,
        IDs[addr].hl.verifies);
    }

    function isMainAccount(address _user) public view returns (bool){
        return DataSet[IDs[_user].baseHash.hash].verify == true;
    }

    function addNewIdentity(bytes32 hashKey, bytes memory _identity, bytes memory _issuer)
        public
        payable
        returns(bool){
        require(IDs[msg.sender].useId != address(0)); // registered user
        uint index = unregister.push(hashKey) - 1;
        UseData memory ud = UseData(_identity, _issuer, false, index, IDs[msg.sender].publicKey);
        DataSet[hashKey] = ud;
        IDs[msg.sender].hl.hashes.push(hashKey);
        IDs[msg.sender].hl.verifies.push(false);
        NewIdentity(msg.sender, hashKey);
        return true;
    }

    function getBaseData(address addr)
        public
        view
        returns(bytes32, bool){
            Hash memory h = IDs[addr].baseHash;
            return (h.hash, h.verify);
        }

    function getHashData(bytes32 hash)
        public
        view
        returns(bytes memory, bytes memory, bool, string memory){
            UseData memory ud = DataSet[hash];
            return (ud.identity, ud.issuer, ud.verify, ud.publicKey);
    }

    function getUnregisterHash()
        public
        view
        returns(bytes32[] memory){
        return unregister;
    }

    function getUnregisterLen()
        public
        view
        returns(uint){
        return unregister.length;
    }

    function verifyBase(address addr)
        public
        onlySigner
        returns(bool){
        require(IDs[addr].useId != address(0));
        IDs[addr].baseHash.verify = true;
        bytes32 h = bytes32(IDs[addr].baseHash.hash);
        DataSet[h].verify = true;
        for(uint i=0; i<IDs[addr].hl.hashes.length; i++){
            if(h == IDs[addr].hl.hashes[i]) {
                IDs[addr].hl.verifies[i] = true;
                return true;
            }
        }
        return false;
    }

    function verifyHash(address addr, bytes32 hash)
        public
        // onlySigner
        onlyCommittee(msg.sender)
        returns(bool){
            require(IDs[addr].useId != address(0));
            require(DataSet[hash].verify == false);
            DataSet[hash].verify = true;
            for(uint i=0; i<IDs[addr].hl.hashes.length; i++){
                if(hash == IDs[addr].hl.hashes[i]){
                    IDs[addr].hl.verifies[i] = true;
                    unregister[DataSet[hash].index] = unregister[unregister.length - 1];        // move the last element to the index
                    DataSet[unregister[unregister.length - 1]].index = DataSet[hash].index;     // update former last emement's index
                    unregister.length--;
                    return true;
                }
            }
        return false;
    }

}
