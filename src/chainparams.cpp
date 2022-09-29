// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"
#include "netbase.h"


SeedSpec6 lookupDomain(const char *name,int port);


static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}


static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Vertoreum / A coin worth collecting";
    const CScript genesisOutputScript = CScript() << ParseHex("04d83ed1b7caee5fe75d94e72fdeef4bec36f59f8f7cac0dae8eb91050023ac1f956e06021f9d754cfa9e6b8a19281fd96235bdbeceefd649557bb96deb336a60c") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 105000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x8b587a7b91d2f397ff6af057b3b86950c3ecde9e13d0c30987d9d12691d0c46a");  // Genesis block
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"); 
        consensus.nPowTargetTimespan =  2 * 24 * 60 * 60;
        consensus.nPowTargetSpacing = 5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 18;
        consensus.nMinerConfirmationWindow = 24;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1664416111;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1664433000;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1664416111;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1664433000;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1664416111;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1664433000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000001abacf1");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0xb1e34a46b3e93a10791969c4fe539f4d4f3c9e6bc3af3335da451208b305bf65");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xf9;
        pchMessageStart[2] = 0xf9;
        pchMessageStart[3] = 0xf9;
        nDefaultPort = 16178;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1664416111, 860, 0x20000fff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x8b587a7b91d2f397ff6af057b3b86950c3ecde9e13d0c30987d9d12691d0c46a"));
        assert(genesis.hashMerkleRoot == uint256S("0x650c8f9ff7eb5b8baa0829f9f9f6170d69be2ad9a930d655a8d6373c1c971b2a"));

        // Note that of those with the service bits flag, most only support a subset of possible options

        vSeeds.push_back(CDNSSeedData("45.77.108.93", "45.77.108.93"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,132);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,123);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,70);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,203);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x03)(0x0e)(0x1e)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0x0e)(0x1f)(0x19).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (  0, uint256S("0x8b587a7b91d2f397ff6af057b3b86950c3ecde9e13d0c30987d9d12691d0c46a"))  // Genesis block
            (  1, uint256S("0x49f8eaf0be0429cbd76266b12a57d15b936a877a5d9218fafa814ba30dace97c"))
            (  16, uint256S("0xa6c3ac85b9a70c86856c15c7fa6578114416061afc864ae6e7b0596f95aecfef")) // SegWit & CSV activation started
            (  48, uint256S("0x747486994821660b8e2907388ac27fc3ba269e508984178facd7ef347cdc7f3f")) // SegWit & CSV locked_in 
            (  72, uint256S("0x3abdf6f0ad65b8e2c661f8d24869f7ebd0c9eed7ce7bac7ca9b6daaeefcedfa7")) // SegWit & CSV active
            (  101, uint256S("0xb1e34a46b3e93a10791969c4fe539f4d4f3c9e6bc3af3335da451208b305bf65")),
        };

        chainTxData = ChainTxData{
            // Data as of block 0
            1664438182, // * UNIX timestamp of last known number of transactions
            102,  // * total number of transactions between genesis and that timestamp
                    //   (the tx=... number in the SetBestChain debug.log lines)
            1.000000  // * estimated number of transactions per second after that timestamp
        };
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 105000;
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x0c3c625b2f209f286441227135050d4f6fa2fded9e3b39f3556e0cf43e240d04");
        consensus.BIP65Height = 0;
        consensus.BIP66Height = 0;
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // 3.5 days
        consensus.nPowTargetSpacing = 0.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 180;
        consensus.nMinerConfirmationWindow = 240;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100010");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0c3c625b2f209f286441227135050d4f6fa2fded9e3b39f3556e0cf43e240d04");

        pchMessageStart[0] = 0xf5;
        pchMessageStart[1] = 0xf5;
        pchMessageStart[2] = 0xf5;
        pchMessageStart[3] = 0xf5;
        nDefaultPort = 26178;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1664416112, 12383, 0x20000fff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0c3c625b2f209f286441227135050d4f6fa2fded9e3b39f3556e0cf43e240d04"));
        assert(genesis.hashMerkleRoot == uint256S("0x650c8f9ff7eb5b8baa0829f9f9f6170d69be2ad9a930d655a8d6373c1c971b2a"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

    //    vSeeds.push_back(CDNSSeedData("", ""));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,64);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,104);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,124);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,204);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x03)(0x13)(0xda)(0xe0).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0x13)(0xdb)(0x65).convert_to_container<std::vector<unsigned char> >();

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, uint256S("0x0c3c625b2f209f286441227135050d4f6fa2fded9e3b39f3556e0cf43e240d04")),
        };

        chainTxData = ChainTxData{
            // Data as of block 0
            1664416112,
            0,
            0.000000
        };

    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 3.5 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 0.5 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000100010");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x50a135afaf6d89f9e5459263a1a01cf26fb319e7f1b7d5b41c950a261eab5d00");

        pchMessageStart[0] = 0xf3;
        pchMessageStart[1] = 0xf3;
        pchMessageStart[2] = 0xf3;
        pchMessageStart[3] = 0xf3;
        nDefaultPort = 36178;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1664416113, 23, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x50a135afaf6d89f9e5459263a1a01cf26fb319e7f1b7d5b41c950a261eab5d00"));
        assert(genesis.hashMerkleRoot == uint256S("0x650c8f9ff7eb5b8baa0829f9f9f6170d69be2ad9a930d655a8d6373c1c971b2a"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true; 

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0x50a135afaf6d89f9e5459263a1a01cf26fb319e7f1b7d5b41c950a261eab5d00"))
        };

        chainTxData = ChainTxData{
            1664416113,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,65);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,105);
        base58Prefixes[SCRIPT_ADDRESS2] = std::vector<unsigned char>(1,125);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,205);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x03)(0x13)(0xda)(0xe0).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x03)(0x13)(0xdb)(0x65).convert_to_container<std::vector<unsigned char> >();

    }

    void UpdateBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
            return mainParams;
    else if (chain == CBaseChainParams::TESTNET)
            return testNetParams;
    else if (chain == CBaseChainParams::REGTEST)
            return regTestParams;
    else
        throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

void UpdateRegtestBIP9Parameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    regTestParams.UpdateBIP9Parameters(d, nStartTime, nTimeout);
}


SeedSpec6 lookupDomain(const char *name,int port){
  SeedSpec6 addrseed;
  CNetAddr addrss;
  LookupHost(name,addrss, true);
  for(int i = 0; i < 16;i++){
    addrseed.addr[15-i] = addrss.GetByte(i);
  }
  addrseed.port = port;
  return addrseed;
}

