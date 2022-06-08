const {expect,assert} = require("chai");
const web3 = require('web3');
const h = require("./helpers/helpers");
const QUERYID1 = h.uintTob32(1)
const abiCoder = new ethers.utils.AbiCoder
const autopayQueryData = abiCoder.encode(["string", "bytes"], ["AutopayAddresses", abiCoder.encode(['bytes'], ['0x'])])
const autopayQueryId = ethers.utils.keccak256(autopayQueryData)

describe("Polygon Governance Function Tests", function() {

  let polyGov, flex, accounts, token, autopay, autopayArray;

  beforeEach(async function() {
    accounts = await ethers.getSigners();
    const Token = await ethers.getContractFactory("StakingToken");
    token = await Token.deploy();
    await token.deployed();
    const PolygonGovernance = await ethers.getContractFactory("Governance");
    const TellorFlex = await ethers.getContractFactory("TellorFlex")
    flex = await TellorFlex.deploy(token.address, accounts[0].address, web3.utils.toWei("10"), 86400 / 2)
    await flex.deployed();
    polyGov = await PolygonGovernance.deploy(flex.address, web3.utils.toWei("10"), accounts[0].address);
    await polyGov.deployed();
    const Autopay = await ethers.getContractFactory("AutopayMock");
    autopay = await Autopay.deploy(token.address);
    await flex.changeGovernanceAddress(polyGov.address);
    await token.mint(accounts[1].address, web3.utils.toWei("1000"));
    autopayArray = abiCoder.encode(["address[]"], [[autopay.address]]);
  });
  it("Test Constructor()", async function() {
    assert(await polyGov.tellor() == flex.address, "tellor address should be correct")
    assert(await polyGov.disputeFee() == web3.utils.toWei("10"), "min dispute fee should be set properly")
    assert(await polyGov.teamMultisig() == accounts[0].address, "team multisig should be set correctly")
  });
  it("Test beginDispute()", async function() {
    await token.connect(accounts[1]).approve(flex.address, web3.utils.toWei("1000"))
    await flex.connect(accounts[1]).depositStake(web3.utils.toWei("10"))
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("100"))
    await token.connect(accounts[1]).transfer(accounts[3].address, web3.utils.toWei("100"))
    let blocky = await h.getBlock()
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    let balance1 = await token.balanceOf(accounts[2].address)
    await h.expectThrow(polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp)) //no value exists
    await flex.connect(accounts[1]).submitValue(QUERYID1, h.bytes(100), 0, '0x')
    blocky = await h.getBlock()
    await h.expectThrow(polyGov.connect(accounts[4]).beginDispute(QUERYID1, blocky.timestamp)) // must have tokens to
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp);
    let balance2 = await token.balanceOf(accounts[2].address)
    let vars = await polyGov.getDisputeInfo(1)
    let _hash = ethers.utils.solidityKeccak256(['bytes32', 'uint256'], [h.uintTob32(1), blocky.timestamp])
    assert(vars[0] == QUERYID1, "queryID should be correct")
    assert(vars[1] == blocky.timestamp, "timestamp should be correct")
    assert(vars[2] == h.bytes(100), "value should be correct")
    assert(vars[3] == accounts[1].address, "accounts[1] should be correct")
    assert(await polyGov.getOpenDisputesOnId(QUERYID1) == 1, "open disputes on ID should be correct")
    assert(await polyGov.getVoteRounds(_hash) == 1, "number of vote rounds should be correct")
    assert(balance1 - balance2 - web3.utils.toWei("10") == 0, "dispute fee paid should be correct")
    await h.advanceTime(86400 * 2);
    await polyGov.tallyVotes(1)
    await h.advanceTime(86400 * 2);
    await polyGov.executeVote(1)
    await h.advanceTime(86400 * 2)
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    await h.expectThrow(polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp)) //assert second dispute started within a day
    await token.connect(accounts[3]).approve(flex.address, web3.utils.toWei("1000"))
    await flex.connect(accounts[3]).depositStake(web3.utils.toWei("10"))
    await flex.connect(accounts[3]).submitValue(QUERYID1, h.bytes(100), 0, '0x')
    blocky = await h.getBlock()
    await h.advanceTime(86400 + 10)
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    await h.expectThrow(polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp)) //fast forward assert
  });
  it("Test executeVote()", async function() {
    await token.connect(accounts[1]).approve(flex.address, web3.utils.toWei("1000"))
    await flex.connect(accounts[1]).depositStake(web3.utils.toWei("10"))
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("100"))
    await token.connect(accounts[1]).transfer(accounts[3].address, web3.utils.toWei("100"))
    let blocky = await h.getBlock()
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    let balance1 = await token.balanceOf(accounts[2].address)
    await h.expectThrow(polyGov.connect(accounts[2]).executeVote(1)) //vote ID must be valid
    await flex.connect(accounts[1]).submitValue(QUERYID1, h.bytes(100), 0, '0x')
    blocky = await h.getBlock()
    await h.expectThrow(polyGov.connect(accounts[4]).beginDispute(QUERYID1, blocky.timestamp)) // must have tokens to
    await polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp);
    let balance2 = await token.balanceOf(accounts[2].address)
    let vars = await polyGov.getDisputeInfo(1)
    let _hash = ethers.utils.solidityKeccak256(['bytes32', 'uint256'], [h.uintTob32(1), blocky.timestamp])
    assert(vars[0] == QUERYID1, "queryID should be correct")
    assert(vars[1] == blocky.timestamp, "timestamp should be correct")
    assert(vars[2] == h.bytes(100), "value should be correct")
    assert(vars[3] == accounts[1].address, "accounts[1] should be correct")
    assert(await polyGov.getOpenDisputesOnId(QUERYID1) == 1, "open disputes on ID should be correct")
    assert(await polyGov.getVoteRounds(_hash) == 1, "number of vote rounds should be correct")
    assert(balance1 - balance2 - web3.utils.toWei("10") == 0, "dispute fee paid should be correct")
    await h.advanceTime(86400 * 2);
    await h.expectThrow(polyGov.connect(accounts[2]).executeVote(1)) //vote must be tallied
    await polyGov.connect(accounts[2]).vote(1, true, false)
    await polyGov.tallyVotes(1)
    await h.advanceTime(86400 * 2);
    await polyGov.executeVote(1)
    await h.expectThrow(polyGov.connect(accounts[2]).executeVote(1)) //vote already executed
    await h.advanceTime(86400 * 2)
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    await h.expectThrow(polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp)) //assert second dispute started within a day
    vars = await polyGov.getVoteInfo(1)
    assert(vars[0] == _hash, "hash should be correct")
    assert(vars[1][0] == 1, "vote round should be correct")
    assert(vars[2][0] == true, "vote should be executed")
    assert(vars[2][1] == true, "is dispute")
    assert(vars[3] == true, "vote should pass")
    await token.connect(accounts[3]).approve(flex.address, web3.utils.toWei("1000"))
    await flex.connect(accounts[3]).depositStake(web3.utils.toWei("10"))
    await flex.connect(accounts[3]).submitValue(QUERYID1, h.bytes(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp) //fast forward assert
    await h.advanceTime(86400 * 2);
    await polyGov.tallyVotes(2)
    await token.connect(accounts[2]).approve(polyGov.address, web3.utils.toWei("20"))
    await polyGov.connect(accounts[2]).beginDispute(QUERYID1, blocky.timestamp)
    await h.advanceTime(86400 * 2);
    await h.expectThrow(polyGov.connect(accounts[2]).executeVote(1)) //vote must be the final vote
    await h.advanceTime(86400 * 2);
    await polyGov.tallyVotes(3)
    await h.advanceTime(86400);
    await h.expectThrow(polyGov.connect(accounts[2]).executeVote(3)) //must wait longer for further rounds
    await h.advanceTime(86400);
    await polyGov.connect(accounts[2]).executeVote(3) //must wait longer for further rounds
  });
  it("Test tallyVotes()", async function() {
    // Test tallyVotes on dispute
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    await polyGov.connect(accounts[1]).vote(1, true, false)
    await h.expectThrow(polyGov.connect(accounts[1]).tallyVotes(1)) // Time for voting has not elapsed
    await h.advanceTime(86400 * 2)
    await polyGov.connect(accounts[1]).tallyVotes(1)
    blocky = await h.getBlock()
    await h.advanceTime(86400)
    voteInfo = await polyGov.getVoteInfo(1)
    assert(voteInfo[3] == 1, "Vote result should change")
    assert(voteInfo[1][4] == blocky.timestamp, "Tally date should be correct")
    await polyGov.executeVote(1)
    await h.expectThrow(polyGov.connect(accounts[1]).tallyVotes(1)) // Dispute has been already executed
  });
  it("Test vote()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    await h.expectThrow(polyGov.connect(accounts[1]).vote(2, true, false)) // Vote does not exist
    await polyGov.connect(accounts[1]).vote(1, true, false)
    await polyGov.connect(accounts[2]).vote(1, false, false)
    await h.expectThrow(polyGov.connect(accounts[1]).vote(1, true, false)) // Sender has already voted
    await h.advanceTime(86400 * 2)
    await polyGov.connect(accounts[1]).tallyVotes(1)
    await h.expectThrow(polyGov.connect(accounts[1]).vote(1, true, false)) // Vote has already been tallied
    voteInfo = await polyGov.getVoteInfo(1)
    assert(voteInfo[1][5] - await token.balanceOf(accounts[1].address) == 0, "Tokenholders doesSupport tally should be correct")
    assert(voteInfo[1][6] == web3.utils.toWei("10"), "Tokenholders doesSupport tally should be correct")
    assert(voteInfo[1][7] == 0, "Tokenholders invalid tally should be correct")
    assert(voteInfo[1][8] == 0, "Users doesSupport tally should be correct")
    assert(voteInfo[1][9] == 0, "Users against tally should be correct")
    assert(voteInfo[1][10] == 0, "Users invalid tally should be correct")
    assert(voteInfo[1][11] == 0, "Reporters doesSupport tally should be correct")
    assert(voteInfo[1][12] == 1, "Reporters against tally should be correct")
    assert(voteInfo[1][13] == 0, "Reporters invalid tally should be correct")
    assert(voteInfo[1][14] == 0, "teamMultisig doesSupport tally should be correct")
    assert(voteInfo[1][15] == 0, "teamMultisig against tally should be correct")
    assert(voteInfo[1][16] == 0, "teamMultisig invalid tally should be correct")
    assert(await polyGov.didVote(1, accounts[1].address), "Voter's voted status should be correct")
    assert(await polyGov.didVote(1, accounts[2].address), "Voter's voted status should be correct")
    assert(await polyGov.didVote(1, accounts[3].address) == false, "Voter's voted status should be correct")
    assert(await polyGov.getVoteTallyByAddress(accounts[1].address) == 1, "Vote tally by address should be correct")
    assert(await polyGov.getVoteTallyByAddress(accounts[2].address) == 1, "Vote tally by address should be correct")
  });
  it("Test didVote()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    assert(await polyGov.didVote(1, accounts[1].address) == false, "Voter's voted status should be correct")
    await polyGov.connect(accounts[1]).vote(1, true, false)
    assert(await polyGov.didVote(1, accounts[1].address), "Voter's voted status should be correct")
  });
  it("Test getDisputeInfo()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    disputeInfo = await polyGov.getDisputeInfo(1)
    assert(disputeInfo[0] == h.uintTob32(1), "Disputed query id should be correct")
    assert(disputeInfo[1] == blocky.timestamp, "Disputed timestamp should be correct")
    assert(disputeInfo[2] == h.uintTob32(100), "Disputed value should be correct")
    assert(disputeInfo[3] == accounts[2].address, "Disputed reporter should be correct")
  });
  it("Test getOpenDisputesOnId()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    assert(await polyGov.getOpenDisputesOnId(h.uintTob32(1)) == 0, "Open disputes on ID should be correct")
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    assert(await polyGov.getOpenDisputesOnId(h.uintTob32(1)) == 1, "Open disputes on ID should be correct")
    await polyGov.connect(accounts[1]).vote(1, true, false)
    await h.advanceTime(86400 * 2)
    await polyGov.connect(accounts[1]).tallyVotes(1)
    await h.advanceTime(86400)
    await polyGov.executeVote(1)
    assert(await polyGov.getOpenDisputesOnId(h.uintTob32(1)) == 0, "Open disputes on ID should be correct")
  });
  it("Test getVoteCount()", async function() {
    assert(await polyGov.getVoteCount() == 0, "Vote count should start at 0")
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    assert(await polyGov.getVoteCount() == 1, "Vote count should increment correctly")
    await h.advanceTime(86400 * 2)
    await polyGov.connect(accounts[1]).tallyVotes(1)
    await h.advanceTime(86400)
    await polyGov.executeVote(1)
    assert(await polyGov.getVoteCount() == 1, "Vote count should not change after vote execution")
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky.timestamp)
    assert(await polyGov.getVoteCount() == 2, "Vote count should increment correctly")
  });
  it("Test getVoteInfo()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky0 = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky0.timestamp)
    blocky1 = await h.getBlock()
    await polyGov.connect(accounts[1]).vote(1, true, false)
    await h.advanceTime(86400 * 7)
    await polyGov.connect(accounts[1]).tallyVotes(1)
    blocky2 = await h.getBlock()
    await h.advanceTime(86400)
    await polyGov.executeVote(1)
    voteInfo = await polyGov.getVoteInfo(1)
    proposalData = abiCoder.encode(['address', 'bool'], [accounts[2].address, 'true'])
    hash = ethers.utils.solidityKeccak256(['bytes32', 'uint256'], [h.uintTob32(1), blocky0.timestamp])
    assert(voteInfo[0] == hash, "Vote hash should be correct")
    assert(voteInfo[1][0] == 1, "Vote round should be correct")
    assert(voteInfo[1][1] == blocky1.timestamp, "Vote start date should be correct")
    assert(voteInfo[1][2] == blocky1.number, "Vote blocknumber should be correct")
    assert(voteInfo[1][3] == web3.utils.toWei("10"), "Vote fee should be correct")
    assert(voteInfo[1][4] == blocky2.timestamp, "Vote tallyDate should be correct")
    assert(voteInfo[1][5] == web3.utils.toWei("970"), "Vote tokenholders doesSupport should be correct")
    assert(voteInfo[1][6] == 0, "Vote tokenholders against should be correct")
    assert(voteInfo[1][7] == 0, "Vote tokenholders invalid should be correct")
    assert(voteInfo[1][8] == 0, "Vote users doesSupport should be correct")
    assert(voteInfo[1][9] == 0, "Vote users against should be correct")
    assert(voteInfo[1][10] == 0, "Vote users invalid should be correct")
    assert(voteInfo[1][11] == 0, "Vote reporters doesSupport should be correct")
    assert(voteInfo[1][12] == 0, "Vote reporters against should be correct")
    assert(voteInfo[1][13] == 0, "Vote reporters invalid should be correct")
    assert(voteInfo[1][14] == 0, "Vote teamMultisig doesSupport should be correct")
    assert(voteInfo[1][15] == 0, "Vote teamMultisig against should be correct")
    assert(voteInfo[1][16] == 0, "Vote teamMultisig invalid should be correct")
    assert(voteInfo[2][0], "Vote executed should be true")
    assert(voteInfo[2][1] == true, "Vote isDispute should be false")
    assert(voteInfo[3] == 1, "Vote result should be PASSED")
    assert(voteInfo[4] == '0x', "Vote proposal data should be correct")
    assert(voteInfo[5] == '0x00000000', "Vote function identifier should be correct")
    assert(voteInfo[6][0] == '0x0000000000000000000000000000000000000000', "Vote destination address should be correct")
    assert(voteInfo[6][1] == accounts[1].address, "Vote initiator address should be correct")
  });
  it("Test getVoteRounds()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky0 = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky0.timestamp)
    blocky1 = await h.getBlock()
    hash = ethers.utils.solidityKeccak256(['bytes32', 'uint256'], [h.uintTob32(1), blocky0.timestamp])
    voteRounds = await polyGov.getVoteRounds(hash)
    assert(voteRounds.length == 1, "Vote rounds length should be correct")
    assert(voteRounds[0] == 1, "Vote rounds disputeIds should be correct")
    await h.advanceTime(86400 * 2)
    await polyGov.connect(accounts[1]).tallyVotes(1)
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("20"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky0.timestamp)
    voteRounds = await polyGov.getVoteRounds(hash)
    assert(voteRounds.length == 2, "Vote rounds length should be correct")
    assert(voteRounds[0] == 1, "Vote round disputeId should be correct")
    assert(voteRounds[1] == 2, "Vote round disputeId should be correct")
  });
  it("Test getVoteTallyByAddress()", async function() {
    await token.connect(accounts[1]).transfer(accounts[2].address, web3.utils.toWei("20"))
    await token.connect(accounts[2]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[2]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[2]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky0 = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky0.timestamp)
    await token.connect(accounts[1]).transfer(accounts[3].address, web3.utils.toWei("20"))
    await token.connect(accounts[3]).approve(flex.address, web3.utils.toWei("20"))
    await flex.connect(accounts[3]).depositStake(web3.utils.toWei("20"))
    await flex.connect(accounts[3]).submitValue(h.uintTob32(1), h.uintTob32(100), 0, '0x')
    blocky0 = await h.getBlock()
    await token.connect(accounts[1]).approve(polyGov.address, web3.utils.toWei("10"))
    await polyGov.connect(accounts[1]).beginDispute(h.uintTob32(1), blocky0.timestamp)
    assert(await polyGov.getVoteTallyByAddress(accounts[1].address) == 0, "Vote tally should be correct")
    await polyGov.connect(accounts[1]).vote(1, true, false)
    assert(await polyGov.getVoteTallyByAddress(accounts[1].address) == 1, "Vote tally should be correct")
    await polyGov.connect(accounts[1]).vote(2, true, false)
    assert(await polyGov.getVoteTallyByAddress(accounts[1].address) == 2, "Vote tally should be correct")
  })
});