#ifndef CEX_XMSSCORE_H
#define CEX_XMSSCORE_H

#include "CexConfig.h"
#include "IPrng.h"
#include "XmssParameters.h"

NAMESPACE_XMSS

using Prng::IPrng;
using Enumeration::XmssParameters;

/// <summary>
/// The XMSS support class
/// </summary>
class XMSSCore
{
private:

	static const size_t XMSS_OID_LEN = 4;
	static const uint32_t XMSS_ADDR_TYPE_OTS = 0;
	static const uint32_t XMSS_ADDR_TYPE_LTREE = 1;
	static const uint32_t XMSS_ADDR_TYPE_HASHTREE = 2;
	static const uint32_t XMSS_PRFCTR_SIZE = 32;
	static const uint32_t XMSS_HASH_PADDING_F = 0;
	static const uint32_t XMSS_HASH_PADDING_H = 1;
	static const uint32_t XMSS_HASH_PADDING_HASH = 2;
	static const uint32_t XMSS_HASH_PADDING_PRF = 3;
	static const uint32_t XMSS_SHA2_256 = 0;
	static const uint32_t XMSS_SHA2_512 = 1;
	static const uint32_t XMSS_SHAKE_128 = 2;
	static const uint32_t XMSS_SHAKE_256 = 3;

	typedef struct
	{
		size_t IndexSize;
		size_t N;
		size_t PublicKeySize;
		size_t SecretKeySize;
		size_t SignatureSize;
		size_t WotsLen1;
		size_t WotsLen2;
		size_t WotsLen;
		size_t WotsSignatureSize;
		uint32_t BdsK;
		uint32_t D;
		uint32_t FullHeight;
		uint32_t HashFunction;
		uint32_t TreeHeight;
		uint32_t WotsW;
		uint32_t WotsLogW;
	} XmssParams;

	// hash.c //

	static void AddressToBytes(std::vector<uint8_t> &Input, const std::array<uint32_t, 8> &Address);

	static int32_t CoreHash(const XmssParams &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, size_t InLength);

	static int32_t Prf(const XmssParams &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, const std::vector<uint8_t> &Key, size_t KeyOffset);

	static int32_t HashMessage(const XmssParams &Params, std::vector<uint8_t> &Output, const std::vector<uint8_t> &R, size_t ROffset, const std::vector<uint8_t> &Root, uint64_t Idx, std::vector<uint8_t> &MsgPrefix,
		size_t MsgOffset, uint64_t Msglength);

	static int32_t ThashH(const XmssParams &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	static int32_t ThashF(const XmssParams &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	// hash_address.c //

	static void SetLayerAddress(std::array<uint32_t, 8> &Address, uint32_t Layer);

	static void SetTreeAddress(std::array<uint32_t, 8> &Address, uint64_t Tree);

	static void SetType(std::array<uint32_t, 8> &Address, uint32_t Type);

	static void SetKeyAndMask(std::array<uint32_t, 8> &Address, uint32_t Mask);

	static void CopySubtreeAdress(std::array<uint32_t, 8> &Output, const std::array<uint32_t, 8> &Input);

	static void SetOtsAddress(std::array<uint32_t, 8> &Address, uint32_t Ots);

	static void SetChainAddress(std::array<uint32_t, 8> &Address, uint32_t Chain);

	static void SetHashAddress(std::array<uint32_t, 8> &Address, uint32_t Hash);

	static void SetLtreeAddress(std::array<uint32_t, 8> &Address, uint32_t Ltree);

	static void SetTreeHeight(std::array<uint32_t, 8> &Address, uint32_t Height);

	static void SetTreeIndex(std::array<uint32_t, 8> &Address, uint32_t Index);

	// params.c //

	static int32_t XmssParseOid(XmssParams &Params, const uint32_t Oid);

	static int32_t XmssMtParseOid(XmssParams &Params, const uint32_t Oid);

	static int32_t InitializeParams(XmssParams &Params);

	// utils.c //

	static void UllToBytes(std::vector<uint8_t> &Output, size_t Offset, size_t Length, uint64_t Input);

	static uint64_t BytesToUll(const std::vector<uint8_t> &Input, size_t Length);

	// wots.c //

	static void ExpandSeed(const XmssParams &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input);

	static void GenChain(const XmssParams &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset,
		uint32_t Start, uint32_t Steps, const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	static void BaseW(const XmssParams &Params, std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<uint8_t> &Input);

	static void WotsChecksum(const XmssParams &Params, std::vector<int32_t> &CsumBaseW, size_t CsumOffset, const std::vector<int32_t> &MsgBaseW);

	static void ChainLengths(const XmssParams &Params, std::vector<int32_t> &Lengths, const std::vector<uint8_t> &Message);

	static void WotsPkGen(const XmssParams &Params, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Seed, const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	static void WotsSign(const XmssParams &Params, std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &Seed,
		const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	static void WotsPkFromSig(const XmssParams &Params, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message,
		const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	// xmss.c //

	static int32_t XmssKeyPair(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &SecretKey, const uint32_t Oid, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssSign(std::vector<uint8_t> &SecretKey, std::vector<uint8_t> &Signature, size_t &SigLength, const std::vector<uint8_t> &Message, size_t MsgLength);

	static int32_t XmssSignOpen(std::vector<uint8_t> &Message, size_t &MsgLength, const std::vector<uint8_t> &Signature, size_t SigLength, const std::vector<uint8_t> &PublicKey);

	static int32_t XmssMtKeyPair(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &SecretKey, const uint32_t Oid, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssMtSign(std::vector<uint8_t> &SecretKey, std::vector<uint8_t> &Signature, size_t &SigLength, const std::vector<uint8_t> &Message, size_t MsgLength);

	static int32_t XmssMtSignOpen(std::vector<uint8_t> &Message, size_t &MsgLength, const std::vector<uint8_t> &Signature, size_t SigLength, const std::vector<uint8_t> &PublicKey);

	// xmms_commons.c //

	static void LTree(const XmssParams &Params, std::vector<uint8_t> &Leaf, size_t LeafOffset, std::vector<uint8_t> &WotsPk, const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	static void ComputeRoot(const XmssParams &Params, std::vector<uint8_t> &Root, const std::vector<uint8_t> &Leaf, uint32_t leafidx, const std::vector<uint8_t> &Authpath, size_t AuthOffset,
		const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &Address);

	static void GenLeafWots(const XmssParams &Params, std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SkSeed, size_t SkOffset,
		const std::vector<uint8_t> &PubSeed, std::array<uint32_t, 8> &lTreeAddr, std::array<uint32_t, 8> &OtsAddr);

	static void GetSeed(const XmssParams &Params, std::vector<uint8_t> &Seed, const std::vector<uint8_t> &SkSeed, size_t SkOffset, std::array<uint32_t, 8> &Address);

	static int32_t XmssCoreSignOpen(const XmssParams &Params, std::vector<uint8_t> &Message, size_t &MsgLength, const std::vector<uint8_t> &Signature, size_t SigLength, const std::vector<uint8_t> &PublicKey);

	static int32_t XmssMtCoreSignOpen(const XmssParams &Params, std::vector<uint8_t> &Message, size_t &MsgLength, const std::vector<uint8_t> &Signature, size_t SigLength, const std::vector<uint8_t> &PublicKey);

	// xmss_core.c //

	static void TreeHash(const XmssParams &Params, std::vector<uint8_t> &Root, size_t RootOffset, std::vector<uint8_t> &AuthPath, size_t AuthOffset, const std::vector<uint8_t> &SkSeed,
		size_t SkOffset, const std::vector<uint8_t> &PubSeed, uint32_t LeafIdx, const std::array<uint32_t, 8> &SubtreeAddress);

	static size_t CoreSkBytes(const XmssParams &Params);

	static int32_t XmssCoreKeyPair(const XmssParams &Params, std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &SecretKey, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssCoreSign(const XmssParams &Params, std::vector<uint8_t> &SecretKey, std::vector<uint8_t> &Signature, size_t &SigLength, const std::vector<uint8_t> &Message, size_t MsgLength);

	static int32_t XmssMtCoreKeyPair(const XmssParams &Params, std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &SecretKey, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssMtCoreSign(const XmssParams &Params, std::vector<uint8_t> &SecretKey, std::vector<uint8_t> &Signature, size_t &SigLength, const std::vector<uint8_t> &Message, size_t MsgLength);

public:

	static size_t GetPublicKeySize(XmssParameters Parameters);

	static size_t GetPrivateKeySize(XmssParameters Parameters);

	static size_t GetSignatureSize(XmssParameters Parameters);

	static void Generate(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, XmssParameters Parameters);

	static size_t Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, XmssParameters Parameters);

	static bool Verify(std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey, XmssParameters Parameters);
};

NAMESPACE_XMSSEND
#endif
