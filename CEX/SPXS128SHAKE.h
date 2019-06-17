#ifndef CEX_SPXS128SHAKE_H
#define CEX_SPXS128SHAKE_H

#include "CexConfig.h"
#include "IKdf.h"
#include "IPrng.h"
#include "SphincsParameters.h"
#include <functional>

NAMESPACE_SPHINCS

using Kdf::IKdf;
using Enumeration::SphincsParameters;

/// <summary>
/// The Sphincs+ fast 256bit support class
/// </summary>
class SPXS128SHAKE
{
private:

	// hash output length in bytes //n=16, sfh=64, d=8, forshgt=15, forstree=10, w=16
	static const size_t SPX_N = 16;
	// height of the hypertree
	static const uint SPX_FULL_HEIGHT = 64;
	// number of subtree layer
	static const uint SPX_D = 8;
	// FORS tree dimensions
	static const uint SPX_FORS_HEIGHT = 15;
	static const uint SPX_FORS_TREES = 10;
	// Winternitz parameter
	static const uint SPX_WOTS_W = 16;
	static const uint SPX_ADDR_BYTES = 32;
	// WOTS parameters
	static const uint SPX_WOTS_LOGW = 4;
	static const uint SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
	// SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1 precomputation
	static const uint SPX_WOTS_LEN2 = 3;
	static const uint SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
	static const uint SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
	static const uint SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;
	// subtree size
	static const uint SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
	// FORS parameters
	static const uint SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
	static const uint SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
	static const uint SPX_FORS_PK_BYTES = SPX_N;
	// resulting SPX sizes
	static const size_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
	static const size_t SPX_PK_BYTES = (2 * SPX_N);
	static const size_t SPX_SK_BYTES = (2 * SPX_N + SPX_PK_BYTES);
	// optionally, signing can be made non-deterministic using optrand.
	// this can help counter side-channel attacks that would benefit from
	// getting a large number of traces when the signer uses the same nodes
	static const uint SPX_OPTRAND_BYTES = 32;
	static const uint SPX_ADDR_TYPE_WOTS = 0;
	static const uint SPX_ADDR_TYPE_WOTSPK = 1;
	static const uint SPX_ADDR_TYPE_HASHTREE = 2;
	static const uint SPX_ADDR_TYPE_FORSTREE = 3;
	static const uint SPX_ADDR_TYPE_FORSPK = 4;
	static const uint CRYPTO_SECRETKEYBYTES = SPX_SK_BYTES;
	static const uint CRYPTO_PUBLICKEYBYTES = SPX_PK_BYTES;
	static const uint CRYPTO_BYTES = SPX_BYTES;

public:

	/// <summary>
	/// The Public Key size
	/// </summary>
	static const int32_t SPHINCS_PUBLICKEY_SIZE = SPX_PK_BYTES;

	/// <summary>
	/// The Private Key size
	/// </summary>
	static const int32_t SPHINCS_SECRETKEY_SIZE = SPX_SK_BYTES;

	/// <summary>
	/// The base Signature size
	/// </summary>
	static const int32_t SPHINCS_SIGNATURE_SIZE = SPX_BYTES;

private:

	static void BaseW(std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<byte> &Input);

	static void ChainLengths(std::vector<int32_t> &Lengths, const std::vector<byte> &Message);

	static void ComputeRoot(std::vector<byte> &Root, size_t RootOffset, const std::vector<byte> &Leaf, uint LeafOffset, uint IdxOffset, 
		const std::vector<byte> &AuthPath, size_t AuthOffset, uint TreeHeight, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address);

	static void ForsGenLeaf(std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, 
		uint AddressIdx, const std::array<uint, 8> &TreeAddress);

	static void ForsGenSk(std::vector<byte> &Secret, size_t SecretOffset, const std::vector<byte> &Seed, std::array<uint, 8> &Address);

	static void ForsPkFromSig(std::vector<byte> &PublicKey, size_t PubKeyOffset, const std::vector<byte> &Signature, size_t SigOffset, 
		const std::array<byte, SPX_FORS_MSG_BYTES> &Message, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress);

	static void ForsSign(std::vector<byte> &Signature, size_t SigOffset, std::vector<byte> &PublicKey, const std::array<byte, SPX_FORS_MSG_BYTES> &Message, 
		const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress);

	static void ForsSkToLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretKey, size_t KeyOffset, const std::vector<byte> &PublicSeed, std::array<uint, 8> &LeafAddress);

	static void GenChain(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, uint Start, uint Steps, 
		const std::vector<byte> &PkSeed, std::array<uint, 8> &Address);

	static void GenMessageRandom(const std::array<byte, SPX_N> &SkPrf, const std::vector<byte> &OptRnd, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength);

	static void HashMessage(std::array<byte, SPX_FORS_MSG_BYTES> &Digest, ulong &Tree, uint &LeafIndex, const std::vector<byte> &Rand, 
		const std::vector<byte> &PublicKey, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength);

	static void MessageToIndices(std::vector<uint> &Indices, const std::array<byte, SPX_FORS_MSG_BYTES> &Messages);

	static void PrfAddress(std::vector<byte> &Output, size_t Offset, const std::vector<byte> &Key, const std::array<uint, 8> &Address);

	static void THash(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const size_t InputBlocks, 
		const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::vector<byte> &Buffer, std::vector<byte> &Mask);

	static void TreeHash(std::vector<byte> &Root, size_t RootOffset, std::vector<byte> &Authpath, size_t AuthOffset, const std::vector<byte> &SkSeed, 
		const std::vector<byte> &PkSeed, uint LeafIndex,
		uint IndexOffset, uint TreeHeight, std::array<uint, 8> & TreeAddress, std::vector<byte> &Stack, std::vector<uint> &Heights,
		std::function<void(std::vector<byte> &, size_t, const std::vector<byte> &, const std::vector<byte> &, uint, std::array<uint, 8> &)> &F);

	static void WotsChecksum(std::vector<int32_t> &CSumBaseW, size_t BaseOffset, const std::vector<int32_t> &MsgBaseW);

	static void WotsGenLeaf(std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint AddressIndex, 
		const std::array<uint, 8> &TreeAddress);

	static void WotsGenPk(std::vector<byte> &PublicKey, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address);

	static void WotsGenSk(std::vector<byte> &Key, size_t Offset, const std::vector<byte> &KeySeed, std::array<uint, 8> &WotsAddress);

	static void WotsPkFromSig(std::vector<byte> &PublicKey, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, 
		const std::vector<byte> &PrivateSeed, std::array<uint, 8> &Address);

	static void WotsSign(std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &SecretSeed, 
		const std::vector<byte> &PublicSeed, std::array<uint, 8> &Address);

public:

	static void XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate);

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, SphincsParameters Parameters);

	static size_t Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, SphincsParameters Parameters);

	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, SphincsParameters Parameters);
};

NAMESPACE_SPHINCSEND
#endif
