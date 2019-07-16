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
class XmssCore
{
private:

	static const size_t XMSS_OID_LEN = 4;
	static const uint XMSS_ADDR_TYPE_OTS = 0;
	static const uint XMSS_ADDR_TYPE_LTREE = 1;
	static const uint XMSS_ADDR_TYPE_HASHTREE = 2;
	static const uint XMSS_PRFCTR_SIZE = 32;
	static const uint XMSS_HASH_PADDING_F = 0;
	static const uint XMSS_HASH_PADDING_H = 1;
	static const uint XMSS_HASH_PADDING_HASH = 2;
	static const uint XMSS_HASH_PADDING_PRF = 3;
	static const uint XMSS_SHA2_256 = 0;
	static const uint XMSS_SHA2_512 = 1;
	static const uint XMSS_SHAKE_128 = 2;
	static const uint XMSS_SHAKE_256 = 3;

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
		uint BdsK;
		uint D;
		uint FullHeight;
		uint HashFunction;
		uint TreeHeight;
		uint WotsW;
		uint WotsLogW;
	} XmssParams;

	// hash.c //

	static void AddressToBytes(std::vector<byte> &Input, const std::array<uint, 8> &Address);

	static int32_t CoreHash(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, size_t InLength);

	static int32_t Prf(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, const std::vector<byte> &Key, size_t KeyOffset);

	static int32_t HashMessage(const XmssParams &Params, std::vector<byte> &Output, const std::vector<byte> &R, size_t ROffset, const std::vector<byte> &Root, ulong Idx, std::vector<byte> &MsgPrefix,
		size_t MsgOffset, ulong Msglength);

	static int32_t ThashH(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	static int32_t ThashF(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	// hash_address.c //

	static void SetLayerAddress(std::array<uint, 8> &Address, uint Layer);

	static void SetTreeAddress(std::array<uint, 8> &Address, ulong Tree);

	static void SetType(std::array<uint, 8> &Address, uint Type);

	static void SetKeyAndMask(std::array<uint, 8> &Address, uint Mask);

	static void CopySubtreeAdress(std::array<uint, 8> &Output, const std::array<uint, 8> &Input);

	static void SetOtsAddress(std::array<uint, 8> &Address, uint Ots);

	static void SetChainAddress(std::array<uint, 8> &Address, uint Chain);

	static void SetHashAddress(std::array<uint, 8> &Address, uint Hash);

	static void SetLtreeAddress(std::array<uint, 8> &Address, uint Ltree);

	static void SetTreeHeight(std::array<uint, 8> &Address, uint Height);

	static void SetTreeIndex(std::array<uint, 8> &Address, uint Index);

	// params.c //

	static int32_t XmssParseOid(XmssParams &Params, const uint Oid);

	static int32_t XmssMtParseOid(XmssParams &Params, const uint Oid);

	static int32_t InitializeParams(XmssParams &Params);

	// utils.c //

	static void UllToBytes(std::vector<byte> &Output, size_t Offset, size_t Length, ulong Input);

	static ulong BytesToUll(const std::vector<byte> &Input, size_t Length);

	// wots.c //

	static void ExpandSeed(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input);

	static void GenChain(const XmssParams &Params, std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset,
		uint Start, uint Steps, const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	static void BaseW(const XmssParams &Params, std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<byte> &Input);

	static void WotsChecksum(const XmssParams &Params, std::vector<int32_t> &CsumBaseW, size_t CsumOffset, const std::vector<int32_t> &MsgBaseW);

	static void ChainLengths(const XmssParams &Params, std::vector<int32_t> &Lengths, const std::vector<byte> &Message);

	static void WotsPkGen(const XmssParams &Params, std::vector<byte> &PublicKey, const std::vector<byte> &Seed, const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	static void WotsSign(const XmssParams &Params, std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &Seed,
		const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	static void WotsPkFromSig(const XmssParams &Params, std::vector<byte> &PublicKey, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message,
		const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	// xmss.c //

	static int32_t XmssKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, const uint Oid, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssSign(std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength);

	static int32_t XmssSignOpen(std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey);

	static int32_t XmssMtKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, const uint Oid, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssMtSign(std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength);

	static int32_t XmssMtSignOpen(std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey);

	// xmms_commons.c //

	static void LTree(const XmssParams &Params, std::vector<byte> &Leaf, size_t LeafOffset, std::vector<byte> &WotsPk, const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	static void ComputeRoot(const XmssParams &Params, std::vector<byte> &Root, const std::vector<byte> &Leaf, uint leafidx, const std::vector<byte> &Authpath, size_t AuthOffset,
		const std::vector<byte> &PubSeed, std::array<uint, 8> &Address);

	static void GenLeafWots(const XmssParams &Params, std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SkSeed, size_t SkOffset,
		const std::vector<byte> &PubSeed, std::array<uint, 8> &lTreeAddr, std::array<uint, 8> &OtsAddr);

	static void GetSeed(const XmssParams &Params, std::vector<byte> &Seed, const std::vector<byte> &SkSeed, size_t SkOffset, std::array<uint, 8> &Address);

	static int32_t XmssCoreSignOpen(const XmssParams &Params, std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey);

	static int32_t XmssMtCoreSignOpen(const XmssParams &Params, std::vector<byte> &Message, size_t &MsgLength, const std::vector<byte> &Signature, size_t SigLength, const std::vector<byte> &PublicKey);

	// xmss_core.c //

	static void TreeHash(const XmssParams &Params, std::vector<byte> &Root, size_t RootOffset, std::vector<byte> &AuthPath, size_t AuthOffset, const std::vector<byte> &SkSeed,
		size_t SkOffset, const std::vector<byte> &PubSeed, uint LeafIdx, const std::array<uint, 8> &SubtreeAddress);

	static size_t CoreSkBytes(const XmssParams &Params);

	static int32_t XmssCoreKeyPair(const XmssParams &Params, std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssCoreSign(const XmssParams &Params, std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength);

	static int32_t XmssMtCoreKeyPair(const XmssParams &Params, std::vector<byte> &PublicKey, std::vector<byte> &SecretKey, std::unique_ptr<Prng::IPrng> &Rng);

	static int32_t XmssMtCoreSign(const XmssParams &Params, std::vector<byte> &SecretKey, std::vector<byte> &Signature, size_t &SigLength, const std::vector<byte> &Message, size_t MsgLength);

public:

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, XmssParameters Parameters);

	static size_t Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, XmssParameters Parameters);

	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, XmssParameters Parameters);
};

NAMESPACE_XMSSEND
#endif
