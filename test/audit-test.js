const { expect, assert } = require("chai");
const { ethers } = require("hardhat");
const web3 = require("web3");
const h = require("./helpers/helpers");
const abiCoder = new ethers.utils.AbiCoder();
const autopayQueryData = abiCoder.encode(
    ["string", "bytes"],
    ["AutopayAddresses", abiCoder.encode(["bytes"], ["0x"])]
);
const autopayQueryId = ethers.utils.keccak256(autopayQueryData);
const TRB_QUERY_DATA_ARGS = abiCoder.encode(
    ["string", "string"],
    ["trb", "usd"]
);
const TRB_QUERY_DATA = abiCoder.encode(
    ["string", "bytes"],
    ["SpotPrice", TRB_QUERY_DATA_ARGS]
);
const TRB_QUERY_ID = ethers.utils.keccak256(TRB_QUERY_DATA);
const ETH_QUERY_DATA_ARGS = abiCoder.encode(
    ["string", "string"],
    ["eth", "usd"]
);
const ETH_QUERY_DATA = abiCoder.encode(
    ["string", "bytes"],
    ["SpotPrice", ETH_QUERY_DATA_ARGS]
);
const ETH_QUERY_ID = ethers.utils.keccak256(ETH_QUERY_DATA);
const MINIMUM_STAKE_AMOUNT = web3.utils.toWei("10");

describe("Governance End-To-End audit Tests", function () {
    let gov, flex, accounts, token, autopay, autopayArray;

    beforeEach(async function () {
        accounts = await ethers.getSigners();
        const Token = await ethers.getContractFactory("StakingToken");
        token = await Token.deploy();
        await token.deployed();
        const Governance = await ethers.getContractFactory("Governance");
        const TellorFlex = await ethers.getContractFactory("TellorFlex");
        flex = await TellorFlex.deploy(
            token.address,
            86400 / 2,
            web3.utils.toWei("100"),
            web3.utils.toWei("10"),
            MINIMUM_STAKE_AMOUNT,
            TRB_QUERY_ID
        );
        await flex.deployed();
        gov = await Governance.deploy(flex.address, accounts[0].address);
        await gov.deployed();
        await flex.init(gov.address);
        const Autopay = await ethers.getContractFactory("AutopayMock");
        autopay = await Autopay.deploy(token.address);
        await token.mint(accounts[1].address, web3.utils.toWei("1000"));
        autopayArray = abiCoder.encode(["address[]"], [[autopay.address]]);
    });

    it("[T-007] Test legitimate users vs malicious actors voting power", async function () {
        // Check if we have enough accounts
        if (accounts.length < 500) {
            console.log("Not enough accounts available. Test skipped.");
            return;
        }

        console.log(`Total accounts available: ${accounts.length}`);

        // Setup accounts with clear separation and no overlap
        const legitimateAutopayUsers = accounts.slice(0, 2);       // 2 legitimate autopay users (0-1)
        const legitimateTokenHolders = accounts.slice(10, 60);     // 50 legitimate token holders (10-59)
        const legitimateReporters = accounts.slice(100, 110);      // 50 legitimate reporters (100-149)
        const multisig = accounts[200];                            // Legitimate multisig (200)

        const maliciousAutopayUsers = accounts.slice(700, 800);    // 100 malicious autopay users (210-229)
        const maliciousRecyclers = accounts.slice(231, 399);       // 168 accounts for recycling (240-289)
        const maliciousReporters = accounts.slice(600, 601);       // 50 malicious reporters (300-349)

        const disputeStarter = accounts[400];                      // Dispute starter (400)
        const valueSubmitter = accounts[401];                      // Value submitter (401)
        const oracleSubmitter = accounts[402];                     // Oracle submitter (402)

        // Setup autopay addresses in oracle
        await token.mint(oracleSubmitter.address, web3.utils.toWei("10"));
        await token.connect(oracleSubmitter).approve(flex.address, web3.utils.toWei("10"));
        await flex.connect(oracleSubmitter).depositStake(web3.utils.toWei("10"));
        await flex.connect(oracleSubmitter).submitValue(autopayQueryId, autopayArray, 0, autopayQueryData);
        await h.advanceTime(86400);

        // Setup legitimate autopay users
        for (let i = 0; i < legitimateAutopayUsers.length; i++) {
            await token.mint(legitimateAutopayUsers[i].address, web3.utils.toWei("1"));
            await token.connect(legitimateAutopayUsers[i]).approve(autopay.address, web3.utils.toWei("1"));
            await autopay.connect(legitimateAutopayUsers[i]).tip(ETH_QUERY_ID, web3.utils.toWei("1"), ETH_QUERY_DATA);
        }

        // Setup legitimate token holders
        for (let i = 0; i < legitimateTokenHolders.length; i++) {
            await token.mint(legitimateTokenHolders[i].address, web3.utils.toWei("20"));
        }

        // Setup legitimate reporters
        for (let i = 0; i < legitimateReporters.length; i++) {
            await token.mint(legitimateReporters[i].address, web3.utils.toWei("10"));
            await token.connect(legitimateReporters[i]).approve(flex.address, web3.utils.toWei("10"));
            await flex.connect(legitimateReporters[i]).depositStake(web3.utils.toWei("10"));
            // Use different query IDs for each reporter to avoid timestamp conflicts
            const uniqueQueryData = `0x${i.toString().padStart(64, '0')}`;
            await flex.connect(legitimateReporters[i]).submitValue(h.hash(uniqueQueryData), h.bytes(100), 0, uniqueQueryData);
        }

        // Setup malicious autopay users (more than legitimate)
        for (let i = 0; i < maliciousAutopayUsers.length; i++) {
            await token.mint(maliciousAutopayUsers[i].address, web3.utils.toWei("1"));
            await token.connect(maliciousAutopayUsers[i]).approve(autopay.address, web3.utils.toWei("1"));
            await autopay.connect(maliciousAutopayUsers[i]).tip(ETH_QUERY_ID, web3.utils.toWei("1"), ETH_QUERY_DATA);
        }

        // Setup malicious reporters (more than legitimate ones)
        for (let i = 0; i < maliciousReporters.length; i++) {
            await token.mint(maliciousReporters[i].address, web3.utils.toWei("10"));
            await token.connect(maliciousReporters[i]).approve(flex.address, web3.utils.toWei("10"));
            await flex.connect(maliciousReporters[i]).depositStake(web3.utils.toWei("10"));
            // Use different query IDs for each reporter
            const uniqueQueryData = `0x${(i + 1000).toString().padStart(64, '0')}`;
            await flex.connect(maliciousReporters[i]).submitValue(h.hash(uniqueQueryData), h.bytes(100), 0, uniqueQueryData);
        }
        await h.advanceTime(86400);

        // Setup malicious recyclers with initial funds (much more than legitimate)
        await token.mint(maliciousRecyclers[0].address, web3.utils.toWei("10000")); // 10x more

        // Submit a value to dispute
        await token.mint(valueSubmitter.address, web3.utils.toWei("10"));
        await token.connect(valueSubmitter).approve(flex.address, web3.utils.toWei("10"));
        await flex.connect(valueSubmitter).depositStake(web3.utils.toWei("10"));
        await flex.connect(valueSubmitter).submitValue(ETH_QUERY_ID, h.bytes(100), 0, ETH_QUERY_DATA);
        const blocky = await h.getBlock();

        // Begin dispute
        await token.mint(disputeStarter.address, web3.utils.toWei("10"));
        await token.connect(disputeStarter).approve(gov.address, web3.utils.toWei("10"));
        await gov.connect(disputeStarter).beginDispute(ETH_QUERY_ID, blocky.timestamp);

        console.log("Dispute started. Beginning voting...");

        // Legitimate votes: all legitimate groups vote in SUPPORT
        for (let i = 0; i < legitimateAutopayUsers.length; i++) {
            await gov.connect(legitimateAutopayUsers[i]).vote(1, true, false);
        }

        for (let i = 0; i < legitimateTokenHolders.length; i++) {
            await gov.connect(legitimateTokenHolders[i]).vote(1, true, false);
        }

        for (let i = 0; i < legitimateReporters.length; i++) {
            await gov.connect(legitimateReporters[i]).vote(1, true, false);
        }

        await gov.connect(multisig).vote(1, true, false);

        console.log("Legitimate voting complete. Now starting malicious voting...");

        // Malicious votes: all malicious actors vote AGAINST
        for (let i = 0; i < maliciousAutopayUsers.length; i++) {
            await gov.connect(maliciousAutopayUsers[i]).vote(1, false, false);
        }

        // Recycle funds across accounts and vote against
        for (let i = 0; i < maliciousRecyclers.length; i++) {
            await gov.connect(maliciousRecyclers[i]).vote(1, false, false);

            if (i < maliciousRecyclers.length - 1) {
                const balance = await token.balanceOf(maliciousRecyclers[i].address);
                await token.connect(maliciousRecyclers[i]).transfer(maliciousRecyclers[i + 1].address, balance);
            }
        }

        for (let i = 0; i < maliciousReporters.length; i++) {
            await gov.connect(maliciousReporters[i]).vote(1, false, false);
        }

        console.log("All voting complete. Tallying votes...");

        // Tally and execute
        await h.advanceTime(86400 * 2);
        await gov.tallyVotes(1);
        await h.advanceTime(86400);
        await gov.executeVote(1);

        // Get vote info
        const voteInfo = await gov.getVoteInfo(1);

        // Log results
        console.log("VOTING RESULTS:");
        console.log("Legitimate tokenholders (support):", voteInfo[1][5].toString());
        console.log("Malicious recyclers (against):", voteInfo[1][6].toString());
        console.log("Legitimate users (support):", voteInfo[1][8].toString());
        console.log("Malicious users (against):", voteInfo[1][9].toString());
        console.log("Legitimate reporters (support):", voteInfo[1][11].toString());
        console.log("Malicious reporters (against):", voteInfo[1][12].toString());
        console.log("Multisig (support):", voteInfo[1][14].toString());
        console.log("Vote outcome:", voteInfo[3] == 1 ? "PASSED" : "FAILED");

        // Check if malicious actors were able to overrule legitimate votes
        if (voteInfo[3] == 0) {
            console.log("ATTACK SUCCESSFUL: Malicious actors overruled legitimate votes");
        } else {
            console.log("ATTACK FAILED: Legitimate votes prevailed");
        }
    });

});

