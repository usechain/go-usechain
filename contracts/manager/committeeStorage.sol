pragma solidity ^0.4.20;

contract committeeStorage {
    /// @notice Committee
    uint constant public MAX_COMMITTEEMAN_COUNT = 5;
    uint constant public Requirement = 3;

    uint constant public Election_cycle = 5256000;
    uint constant public Election_duration = 432000;

    /// @notice Signle Mode, Multi Mode or Product Mode
    // 0: Product Mode, full check
    // 1: Signle Mode, only one committee, and checkpoint only need one committee confirm
    uint public mode = 0;

    /// @notice Vote
    bool public vote_enabled = true;

    /// @notice Committee On Duty
    address[MAX_COMMITTEEMAN_COUNT] public committeeOnDuty;

    /// @dev Committee
    struct Committee {
        bool confirmed;
        address addr;
        string asymPubkey;
    }

    /// @dev Election round
    struct Round {
        address[] candidate;
        mapping(address => uint) votes;    //candidate's vote count
        mapping(address => bool) voted;    //voter whether voted already

        bool selected;
        Committee[MAX_COMMITTEEMAN_COUNT] committees;

        string committeePublicKey;
        string committeePublicKey_candidate;
        mapping(address => bool) pubKeyConfirmed;
        uint confirmCount;
    }
    mapping(uint => Round) public rounds;

    /// @notice In which round now
    function whichRound()
    internal
    view
    returns(uint)
    {
        return block.number/Election_cycle;
    }

    // @notice whether main account
    /// TODO: add it
    modifier isMainAccount() {
        require(true);
        _;
    }

    /****************initial*********************/
    /// @notice in first 1000 blocks
    modifier inFirst1000Blocks() {
        require(block.number <= 1000);
        _;
    }

    /// @notice initial member set
    // only can do in first 1000 block, just for committee initial
    function initial(address[] _candidate)
    inFirst1000Blocks
    public
    {
        require(_candidate.length == MAX_COMMITTEEMAN_COUNT);
        rounds[0].selected = true;
        for(uint i=0; i<MAX_COMMITTEEMAN_COUNT;i++){
        rounds[0].committees[i].addr = _candidate[i];
    }
    }

    /****************voting*********************/
    /// @notice voting now?
    modifier isVoting() {
        //require(block.number%Election_cycle <= Election_duration);
        require(vote_enabled);
        _;
    }

    /// @notice not voting
    modifier notVoting() {
        //require(block.number%Election_cycle > Election_duration);
        require(!vote_enabled);
        _;
    }

    /// @notice can't vote twice in one round
    modifier notVoted() {
        require(rounds[whichRound()].voted[msg.sender] == false);
        _;
    }

    /// @notice committee already been selected
    modifier notSelected() {
        require(rounds[whichRound()].selected == false);
        _;
    }

    /// @notice start vote or stop it
    function controlVote(bool _flag) public {
        vote_enabled = _flag;
    }

    function getBlockNumber() public view returns(uint) {
        return block.number;
    }

    /// @notice votes
    function vote(address _candidate)
    isMainAccount
    isVoting
    notVoted
    public
    returns(bool){
        // which round
        uint roundIndex = whichRound();
        if(rounds[roundIndex].votes[_candidate] == 0) {
            rounds[roundIndex].candidate.push(_candidate);
        }
        rounds[roundIndex].votes[_candidate]++;
        rounds[roundIndex].voted[msg.sender] = true;

        // check whether candidate in committee list or not
        for(uint i=0; i<MAX_COMMITTEEMAN_COUNT;i++) {
            if(rounds[roundIndex].committees[i].addr == _candidate) {
                return true;
            }
            if(rounds[roundIndex].committees[i].addr == address(0)) {
                rounds[roundIndex].committees[i].addr = _candidate;
                return true;
            }
        }

        // sort
        reSort(roundIndex, _candidate);
        return true;
    }

    /// @dev do sort at each tx
    function reSort(uint _roundIndex, address _candidate)
    internal {
        // init min
        uint minIndex = 0;
        address minCandidate = rounds[_roundIndex].committees[0].addr;
        uint minVotes = rounds[_roundIndex].votes[minCandidate];

        // reindex min
        for(uint i=1; i<MAX_COMMITTEEMAN_COUNT;i++){
            minCandidate = rounds[_roundIndex].committees[i].addr;
            if(minVotes > rounds[_roundIndex].votes[minCandidate]) {
                minVotes = rounds[_roundIndex].votes[minCandidate];
                minIndex = i;
            }
        }
        minCandidate = rounds[_roundIndex].committees[minIndex].addr;
        // update
        if (minVotes < rounds[_roundIndex].votes[_candidate]) {
            rounds[_roundIndex].committees[minIndex].addr = _candidate;
            rounds[_roundIndex].committees[minIndex].confirmed = false;
            rounds[_roundIndex].committees[minIndex].asymPubkey = "";
        }
    }

    /// @notice confirm votes after election ends
    function confirmVoting()
    notVoting
    notSelected
    public
    {
        uint roundIndex = whichRound();
        rounds[roundIndex].selected = true;
    }

    /// @notice get address's votes
    function getVotes(address _candidate)
    public
    view
    returns(uint)
    {
        return rounds[whichRound()].votes[_candidate];
    }

    // @test
    function getCandidateLen()
    public
    view
    returns(uint)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].candidate.length;
    }

    /// @notice test
    function getCandidate(uint _index)
    public
    view
    returns(address)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].candidate[_index];
    }

    /****************committes*********************/
    /// @notice whether a committes now
    modifier isCommittee() {
        require(getCommitteeIndex() != -1);
        _;
    }

    /// @notice whether a committes now
    function IsCommittee()
    public
    view
    returns(bool)
    {
        return  getCommitteeIndex() != -1;
    }

    /// @notice whether msg.sender is an on duty committee
    function IsOndutyCommittee(address _user)
    public
    view
    returns(bool)
    {
        for (uint i=0; i<MAX_COMMITTEEMAN_COUNT; i++) {
        if (committeeOnDuty[i] == _user) {
            return true;
        }
    }
        return false;
    }

    /// @notice test
    function getCommittee(uint _index)
    public
    view
    returns(address)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].committees[_index].addr;
    }

    /// @notice whether a committes now
    function getCommitteeIndex()
    internal
    view
    returns(int)
    {
        for(uint i = 0; i < MAX_COMMITTEEMAN_COUNT; i++) {
        // if(committeeOnDuty[i] == msg.sender) {
        if (rounds[whichRound()].committees[i].addr == msg.sender) {
            return int(i);
        }
    }
        return -1;
    }

    /// @notice check the committee whether confirmed
    function getCommitteeConfirmStat()
    public
    view
    returns(bool)
    {
        uint roundIndex = whichRound();
        uint committeeIndex = uint(getCommitteeIndex());
        return rounds[roundIndex].committees[committeeIndex].confirmed;
    }

    /// @notice confirm & upload whisper asymPubkey
    function confirmAndKeyUpload(string memory _asymPubkey)
    isCommittee
    public
    {
        uint roundIndex = whichRound();
        uint committeeIndex = uint(getCommitteeIndex());
        rounds[roundIndex].committees[committeeIndex].confirmed = true;
        rounds[roundIndex].committees[committeeIndex].asymPubkey = _asymPubkey;
        //on duty
        if(isEntireConfirmed() == true) {
            // @notice update committee into on duty array
            for(uint i = 0; i < MAX_COMMITTEEMAN_COUNT; i++) {
                committeeOnDuty[i] = rounds[roundIndex].committees[i].addr;
            }
        }
    }

    /// @notice get committee asym key
    function getCommitteeAsymkey(uint index)
    public
    view
    returns(string memory)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].committees[index].asymPubkey;
    }

    /// @dev Check whether all committee confirmed&&uploaded
    function isEntireConfirmed()
    public
    view
    returns(bool)
    {
        uint roundIndex = whichRound();
        for(uint i = 0; i < MAX_COMMITTEEMAN_COUNT; i++) {
        if (rounds[roundIndex].committees[i].confirmed == false) {
            return false;
        }
    }
        return true;
    }


    /*****************committeePublicKey upload & confirm********************/
    /// @dev upload committee's personal public key
    function uploadCommitteePubkey(string memory _pubkey)
    isCommittee
    public
    {
        uint roundIndex = whichRound();
        require(isEntireConfirmed() == true);
        rounds[roundIndex].committeePublicKey = _pubkey;
        // uint roundIndex = whichRound();
        // rounds[roundIndex].committeePublicKey_candidate = _pubkey;
        // rounds[roundIndex].pubKeyConfirmed[msg.sender] = true;
        // rounds[roundIndex].confirmCount == 1;
    }

    /// @dev confirm the committee public key
    /// TODO: Not used yet
    function confirmCommitteePubkey(string memory _pubkey)
    public
    {
        uint roundIndex = whichRound();
        if(keccak256(rounds[roundIndex].committeePublicKey_candidate) != keccak256(_pubkey)) {
            return;
        }
        rounds[roundIndex].committeePublicKey_candidate = _pubkey;
        rounds[roundIndex].pubKeyConfirmed[msg.sender] = true;
        rounds[roundIndex].confirmCount ++;

        if(rounds[roundIndex].confirmCount >= Requirement) {
            rounds[roundIndex].committeePublicKey = rounds[roundIndex].committeePublicKey_candidate;
        }
    }

    /// @dev get the current committeePublicKey
    function getCommitteePubkey()
    public
    view
    returns(string memory)
    {
        uint roundIndex = whichRound();
        return rounds[roundIndex].committeePublicKey;
    }
}