#ifndef CEX_SPXF256_H
#define CEX_SPXF256_H

#include "CexConfig.h"
#include "IKdf.h"
#include "IPrng.h"


NAMESPACE_SPHINCS

using Kdf::IKdf;


/// <summary>
/// The Sphincs+ fast 256bit support class
/// </summary>
class SPXF256
{
private:

	// hash output length in bytes
	static const int32_t SPX_N = 32;
	// height of the hypertree
	static const int32_t SPX_FULL_HEIGHT = 68;
	// number of subtree layer
	static const int32_t SPX_D = 17;
	// FORS tree dimensions
	static const int32_t SPX_FORS_HEIGHT = 10;
	static const int32_t SPX_FORS_TREES = 30;
	// Winternitz parameter
	static const int32_t SPX_WOTS_W = 16;
	static const int32_t SPX_ADDR_BYTES = 32;
	// WOTS parameters
	static const int32_t SPX_WOTS_LOGW = 4;
	static const int32_t SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
	// SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1 precomputation
	static const int32_t SPX_WOTS_LEN2 = 3;
	static const int32_t SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
	static const int32_t SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
	static const int32_t SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;
	// subtree size
	static const int32_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
	// FORS parameters
	static const int32_t SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
	static const int32_t SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
	static const int32_t SPX_FORS_PK_BYTES = SPX_N;
	// resulting SPX sizes
	static const int32_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
	static const int32_t SPX_PK_BYTES = (2 * SPX_N);
	static const int32_t SPX_SK_BYTES = (2 * SPX_N + SPX_PK_BYTES);
	// optionally, signing can be made non-deterministic using optrand.
	// this can help counter side-channel attacks that would benefit from
	// getting a large number of traces when the signer uses the same nodes
	static const int32_t SPX_OPTRAND_BYTES = 32;
	static const int32_t SPX_ADDR_TYPE_WOTS = 0;
	static const int32_t SPX_ADDR_TYPE_WOTSPK = 1;
	static const int32_t SPX_ADDR_TYPE_HASHTREE = 2;
	static const int32_t SPX_ADDR_TYPE_FORSTREE = 3;
	static const int32_t SPX_ADDR_TYPE_FORSPK = 4;
	static const int32_t CRYPTO_SECRETKEYBYTES = SPX_SK_BYTES;
	static const int32_t CRYPTO_PUBLICKEYBYTES = SPX_PK_BYTES;
	static const int32_t CRYPTO_BYTES = SPX_BYTES;

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

	static void AddressToBytes(std::vector<byte> &Output, size_t Offset, const std::array<uint, 8> &Address);

	static void BaseW(std::vector<int> &Output, size_t OutOffset, const size_t OutLength, const std::vector<byte> &Input);

	static void ChainLengths(std::vector<int> &Lengths, const std::vector<byte> &Message);

	static void ComputeRoot(std::vector<byte> &Root, size_t RootOffset, const std::vector<byte> &Leaf, uint LeafOffset, uint IdxOffset, const std::vector<byte> &AuthPath, size_t AuthOffset, uint TreeHeight, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);

	static void ForsGenLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, uint AddressIdx, const std::array<uint, 8> &TreeAddress, std::unique_ptr<IKdf> &Generator);

	static void ForsGenSk(std::vector<byte> &Secret, size_t SecretOffset, const std::vector<byte> &Seed, std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);

	static void ForsPkFromSig(std::vector<byte> &PublicKey, size_t PubKeyOffset, const std::vector<byte> &Signature, size_t SigOffset, const std::array<byte, SPX_FORS_MSG_BYTES> &Message, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, std::unique_ptr<IKdf> &Generator);

	static void ForsSign(std::vector<byte> &Signature, size_t SigOffset, std::vector<byte> &PublicKey, const std::array<byte, SPX_FORS_MSG_BYTES> &Message, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, std::unique_ptr<IKdf> &Generator);

	static void ForsSkToLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretKey, size_t KeyOffset, const std::vector<byte> &PublicSeed, std::array<uint, 8> &LeafAddress, std::unique_ptr<IKdf> &Generator);

	static void GenChain(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, uint Start, uint Steps, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);

	static void GenMessageRandom(const std::array<byte, SPX_N> &SkPrf, const std::vector<byte> &OptRnd, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, std::unique_ptr<IKdf> &Generator);

	static void HashMessage(std::array<byte, SPX_FORS_MSG_BYTES> &Digest, ulong &Tree, uint &LeafIndex, const std::vector<byte> &Rand, const std::vector<byte> &PublicKey, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, std::unique_ptr<IKdf> &Generator);

	static void MessageToIndices(std::vector<uint> &Indices, const std::array<byte, SPX_FORS_MSG_BYTES> &Messages);

	static void PrfAddress(std::vector<byte> &Output, size_t Offset, const std::vector<byte> &Key, const std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);

	static void THash(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const uint InputBlocks, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::vector<byte> &Buffer, std::vector<byte> &Mask, std::unique_ptr<IKdf> &Generator);

	static void TreeHashF(std::vector<byte> &Root, size_t RootOffset, std::vector<byte> &Authpath, size_t AuthOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint LeafIndex,
		uint IndexOffset, uint TreeHeight, std::array<uint, 8> &TreeAddress, std::vector<byte> &Stack, std::vector<uint> &Heights, std::unique_ptr<IKdf> &Generator);

	static void TreeHashW(std::vector<byte> &Root, std::vector<byte> &Authpath, size_t AuthOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint LeafIndex,
		uint IndexOffset, uint TreeHeight, std::array<uint, 8> &TreeAddress, std::vector<byte> &Stack, std::vector<uint> &Heights, std::unique_ptr<IKdf> &Generator);

	static void WotsChecksum(std::vector<int> &CSumBaseW, size_t BaseOffset, const std::vector<int> &MsgBaseW);

	static void WotsGenLeaf(std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint AddressIndex, const std::array<uint, 8> &TreeAddress, std::unique_ptr<IKdf> &Generator);

	static void WotsGenPk(std::vector<byte> &PublicKey, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);

	static void WotsGenSk(std::vector<byte> &Key, size_t Offset, const std::vector<byte> &KeySeed, std::array<uint, 8> &WotsAddress, std::unique_ptr<IKdf> &Generator);

	static void WotsPkFromSig(std::vector<byte> &PublicKey, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &PrivateSeed, std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);
	
	static void WotsSign(std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, std::array<uint, 8> &Address, std::unique_ptr<IKdf> &Generator);

public:

	static void Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, std::unique_ptr<IKdf> &Generator);

	static size_t Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, std::unique_ptr<IKdf> &Generator);

	static uint Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, std::unique_ptr<IKdf> &Generator);
};

NAMESPACE_SPHINCSEND
#endif


/*
	static void addr_to_bytes(uint8_t* bytes, const uint addr[8])
	{
		size_t i;

		for (i = 0; i < 8; i++)
		{
			SphincsUtils::ull_to_bytes(bytes + (i * 4), 4, addr[i]);
		}
	}

	static void base_w(int32_t* output, const size_t outlen, const uint8_t* input)
	{
		size_t i;
		int32_t bits;
		int32_t inoffset;
		int32_t outoffset;
		uint8_t total;

		bits = 0;
		inoffset = 0;
		outoffset = 0;
		total = 0;

		for (i = 0; i < outlen; ++i)
		{
			if (bits == 0)
			{
				total = input[inoffset];
				inoffset++;
				bits += 8;
			}

			bits -= SPX_WOTS_LOGW;
			output[outoffset] = (total >> bits) & (SPX_WOTS_W - 1);
			++outoffset;
		}
	}

	static void chain_lengths(int32_t* lengths, const uint8_t* msg)
	{
		base_w(lengths, SPX_WOTS_LEN1, msg);
		wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
	}

	static void compute_root(uint8_t* root, const uint8_t* leaf, uint leafidx, uint idxoffset, const uint8_t* authpath, uint treeheight, const uint8_t* pkseed, uint addr[8])
	{
		uint8_t buf1[2 * SPX_N];
		uint8_t buf2[SPX_N + SPX_ADDR_BYTES + 2 * SPX_N];
		uint8_t mask[2 * SPX_N];
		size_t i;

		// If leafidx is odd (last bit = 1), current path element is a right child
		//   and authpath has to go left. Otherwise it is the other way around.
		if (leafidx & 1)
		{
			memcpy(buf1 + SPX_N, leaf, SPX_N);
			memcpy(buf1, authpath, SPX_N);
		}
		else
		{
			memcpy(buf1, leaf, SPX_N);
			memcpy(buf1 + SPX_N, authpath, SPX_N);
		}

		authpath += SPX_N;

		for (i = 0; i < treeheight - 1; i++)
		{
			leafidx >>= 1;
			idxoffset >>= 1;
			// Set the address of the node we're creating.
			SphincsUtils::set_tree_height(addr, i + 1);
			SphincsUtils::set_tree_index(addr, leafidx + idxoffset);

			// Pick the right or left neighbor, depending on parity of the node.

			if (leafidx & 1)
			{
				thash(buf1 + SPX_N, buf1, 2, pkseed, addr, buf2, mask);
				memcpy(buf1, authpath, SPX_N);
			}
			else
			{
				thash(buf1, buf1, 2, pkseed, addr, buf2, mask);
				memcpy(buf1 + SPX_N, authpath, SPX_N);
			}

			authpath += SPX_N;
		}

		// The last iteration is exceptional; we do not copy an authpath node.
		leafidx >>= 1;
		idxoffset >>= 1;
		SphincsUtils::set_tree_height(addr, treeheight);
		SphincsUtils::set_tree_index(addr, leafidx + idxoffset);
		thash(root, buf1, 2, pkseed, addr, buf2, mask);
	}

	static void fors_gen_leaf(uint8_t* leaf, const uint8_t* secretseed, const uint8_t* publicseed, uint addressidx, const uint* treeaddress)
	{
		uint leafaddress[8] = { 0 };

		// Only copy the parts that must be kept in fors_leaf_addr.
		SphincsUtils::copy_keypair_addr(leafaddress, treeaddress);
		SphincsUtils::set_type(leafaddress, SPX_ADDR_TYPE_FORSTREE);
		SphincsUtils::set_tree_index(leafaddress, addressidx);
		fors_gen_sk(leaf, secretseed, leafaddress);
		fors_sk_to_leaf(leaf, leaf, publicseed, leafaddress);
	}

	static void fors_gen_sk(uint8_t* secretkey, const uint8_t* secretseed, uint* forsaddress)
	{
		prf_addr(secretkey, secretseed, forsaddress);
	}

	static void fors_pk_from_sig(uint8_t* publickey, const uint8_t* signature, const uint8_t* m, const uint8_t* pub_seed, const uint* forsaddress)
	{
		uint forstreeaddr[8] = { 0 };
		uint forspkaddr[8] = { 0 };
		uint indices[SPX_FORS_TREES];
		uint8_t leaf[SPX_N];
		uint8_t roots[SPX_FORS_TREES * SPX_N];
		uint idxoffset;
		uint i;

		SphincsUtils::copy_keypair_addr(forstreeaddr, forsaddress);
		SphincsUtils::copy_keypair_addr(forspkaddr, forsaddress);
		SphincsUtils::set_type(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
		SphincsUtils::set_type(forspkaddr, SPX_ADDR_TYPE_FORSPK);
		message_to_indices(indices, m);

		for (i = 0; i < SPX_FORS_TREES; i++)
		{
			idxoffset = i * (1 << SPX_FORS_HEIGHT);
			SphincsUtils::set_tree_height(forstreeaddr, 0);
			SphincsUtils::set_tree_index(forstreeaddr, indices[i] + idxoffset);
			// Derive the leaf from the included secret key part.
			fors_sk_to_leaf(leaf, signature, pub_seed, forstreeaddr);
			signature += SPX_N;
			// Derive the corresponding root node of this tree.
			compute_root(roots + (i * SPX_N), leaf, indices[i], idxoffset, signature, SPX_FORS_HEIGHT, pub_seed, forstreeaddr);
			signature += SPX_N * SPX_FORS_HEIGHT;
		}

		// Hash horizontally across all tree roots to derive the public key.
		uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_FORS_TREES * SPX_N];
		uint8_t mask[SPX_FORS_TREES * SPX_N];
		thash(publickey, roots, SPX_FORS_TREES, pub_seed, forspkaddr, buf, mask);
	}

	static void fors_sign(uint8_t* signature, uint8_t* publickey, const uint8_t* message, const uint8_t* skseed, const uint8_t* pkseed, const uint* forsaddress)
	{
		uint forstreeaddr[8] = { 0 };
		uint forspkaddr[8] = { 0 };
		uint heights[SPX_FORS_HEIGHT + 1];
		uint indices[SPX_FORS_TREES];
		uint8_t roots[SPX_FORS_TREES * SPX_N];
		uint8_t stack[(SPX_FORS_HEIGHT + 1) * SPX_N];
		uint idxoffset;
		uint i;

		SphincsUtils::copy_keypair_addr(forstreeaddr, forsaddress);
		SphincsUtils::copy_keypair_addr(forspkaddr, forsaddress);
		SphincsUtils::set_type(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
		SphincsUtils::set_type(forspkaddr, SPX_ADDR_TYPE_FORSPK);
		message_to_indices(indices, message);

		for (i = 0; i < SPX_FORS_TREES; i++)
		{
			idxoffset = i * (1 << SPX_FORS_HEIGHT);
			SphincsUtils::set_tree_height(forstreeaddr, 0);
			SphincsUtils::set_tree_index(forstreeaddr, indices[i] + idxoffset);
			// Include the secret key part that produces the selected leaf node.
			fors_gen_sk(signature, skseed, forstreeaddr);
			signature += SPX_N;
			// Compute the authentication path for this leaf node.
			treehash(roots + (i * SPX_N), signature, skseed, pkseed, indices[i], idxoffset, SPX_FORS_HEIGHT, forstreeaddr, stack, heights, fors_gen_leaf);
			signature += SPX_N * SPX_FORS_HEIGHT;
		}

		// Hash horizontally across all tree roots to derive the public key.
		uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_FORS_TREES * SPX_N];
		uint8_t mask[SPX_FORS_TREES * SPX_N];
		thash(publickey, roots, SPX_FORS_TREES, pkseed, forspkaddr, buf, mask);
	}

	static void fors_sk_to_leaf(uint8_t* leaf, const uint8_t* secretkey, const uint8_t* publicseed, uint* leafaddress)
	{
		uint8_t buf[SPX_N + SPX_ADDR_BYTES + 1 * SPX_N];
		uint8_t mask[1 * SPX_N];

		thash(leaf, secretkey, 1, publicseed, leafaddress, buf, mask);
	}

	 // Computes the chaining function.
	 // out and in have to be n-byte arrays.
	 //
	 // Interprets in as start-th value of the chain.
	 // addr has to contain the address of the chain.
	static void gen_chain(uint8_t* output, const uint8_t* input, uint start, uint steps, const uint8_t* pkseed, uint addr[8])
	{
		uint8_t buf[SPX_N + SPX_ADDR_BYTES + 1 * SPX_N];
		uint8_t mask[1 * SPX_N];
		uint i;

		// Initialize out with the value at position 'start'.
		memcpy(output, input, SPX_N);

		// Iterate 'steps' calls to the hash function.
		for (i = start; i < (start + steps) && i < SPX_WOTS_W; ++i)
		{
			SphincsUtils::set_hash_addr(addr, i);
			thash(output, output, 1, pkseed, addr, buf, mask);
		}
	}

	 // Computes the message-dependent randomness R, using a secret seed and an
	 // optional randomization value prefixed to the message.
	 // This requires m to have at least 2*SPX_N bytes * bytes of space available in
	 // front of the pointer, i.e. before the message to use for the prefix. This is
	 // necessary to prevent having to move the message around (and allocate memory
	 // for it).
	static void gen_message_random(uint8_t* R, const uint8_t* sk_prf, const uint8_t* optrand, uint8_t* m, ulong mlen)
	{
		std::memcpy(m - (2 * SPX_N), sk_prf, SPX_N);
		std::memcpy(m - SPX_N, optrand, SPX_N);
		shake256(R, SPX_N, m - (2 * SPX_N), mlen + (2 * SPX_N));
	}

	int gen_random(byte* buf, size_t len)
	{
		Prng::SecureRandom rnd(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
		std::vector<byte> tmp(len);
		rnd.Generate(tmp);
		memcpy(buf, tmp.data(), len);

		return 1;
	}

	 // Computes the message hash using R, the public key, and the message.
	 // Notably, it requires m to have SPX_N + SPX_PK_BYTES bytes of space available
	 // in front of the pointer, i.e. before the message, to use for the prefix.
	 // This is necessary to prevent having to move the * message around (and
	 // allocate memory for it).
	 // Outputs the message digest and the index of the leaf. The index is split in
	 // the tree index and the leaf index, for convenient copying to an address.
	static void hash_message(uint8_t* digest, ulong* tree, uint* leaf_idx, const uint8_t* R, const uint8_t* pk, uint8_t* m, ulong mlen)
	{
		static const int32_t SPX_TREE_BITS = (SPX_TREE_HEIGHT * (SPX_D - 1));
		static const int32_t SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8);
		static const int32_t SPX_LEAF_BITS = SPX_TREE_HEIGHT;
		static const int32_t SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8);
		static const int32_t SPX_DGST_BYTES = (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES);

		uint8_t buf[SPX_DGST_BYTES];
		uint8_t *bufp = buf;

		memcpy(m - SPX_N - SPX_PK_BYTES, R, SPX_N);
		memcpy(m - SPX_PK_BYTES, pk, SPX_PK_BYTES);
		shake256(buf, SPX_DGST_BYTES, m - SPX_N - SPX_PK_BYTES, mlen + SPX_N + SPX_PK_BYTES);
		memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
		bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

		*tree = SphincsUtils::bytes_to_ull(bufp, SPX_TREE_BYTES);
		*tree &= (~(ulong)0) >> (64 - SPX_TREE_BITS);
		bufp += SPX_TREE_BYTES;
		*leaf_idx = SphincsUtils::bytes_to_ull(bufp, SPX_LEAF_BYTES);
		*leaf_idx &= (~(uint)0) >> (32 - SPX_LEAF_BITS);
	}

	// For SHAKE256, there is no immediate reason to initialize at the start,
	//   so this function is an empty operation.
	static void initialize_hash_function(const uint8_t* pkseed, const uint8_t* skseed)
	{
		(void)pkseed; // Suppress an 'unused parameter' warning.
		(void)skseed;  // Suppress an 'unused parameter' warning.
	}

	 // Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
	 // Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 // Assumes indices has space for SPX_FORS_TREES integers.
	static void message_to_indices(uint* indices, const uint8_t* messages)
	{
		uint offset;
		size_t i;
		size_t j;

		offset = 0;

		for (i = 0; i < SPX_FORS_TREES; i++)
		{
			indices[i] = 0;
			for (j = 0; j < SPX_FORS_HEIGHT; j++)
			{
				indices[i] <<= 1;
				indices[i] ^= (messages[offset >> 3] >> (offset & 0x7)) & 0x1;
				offset++;
			}
		}
	}

	 // Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
	static void prf_addr(uint8_t* out, const uint8_t* key, const uint addr[8])
	{
		uint8_t buf[SPX_N + SPX_ADDR_BYTES];

		memcpy(buf, key, SPX_N);
		addr_to_bytes(buf + SPX_N, addr);

		shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
	}

	 // Takes an array of inblocks concatenated arrays of SPX_N bytes.
	static void thash(uint8_t* out, const uint8_t* in, const uint inblocks, const uint8_t* pub_seed, uint addr[8], uint8_t* buf, uint8_t* mask)
	{
		uint i;

		memset(buf, 0, sizeof(buf));
		memset(mask, 0, sizeof(mask));
		memcpy(buf, pub_seed, SPX_N);

		addr_to_bytes(buf + SPX_N, addr);
		shake256(mask, inblocks * SPX_N, buf, SPX_N + SPX_ADDR_BYTES);

		for (i = 0; i < inblocks * SPX_N; i++)
		{
			buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ mask[i];
		}

		shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
	}

	 // For a given leaf index, computes the authentication path and the resulting
	 // root node using Merkle's TreeHash algorithm.
	 // Expects the layer and tree parts of the tree_addr to be set, as well as the
	 // tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
	 // Applies the offset idx_offset to indices before building addresses, so that
	 // it is possible to continue counting indices across trees.
	static void treehash(uint8_t* root, uint8_t* authpath, const uint8_t* skseed, const uint8_t* pkseed, uint leafidx,
		uint idxoffset, uint treeheight, uint treeaddr[8], uint8_t* stack, uint* heights,
		void(*gen_leaf)(uint8_t*, const uint8_t*, const uint8_t*, uint, const uint[8]))
	{
		uint8_t buf[SPX_N + SPX_ADDR_BYTES + 2 * SPX_N];
		uint8_t mask[2 * SPX_N];
		uint offset;
		uint idx;
		uint treeidx;

		offset = 0;

		for (idx = 0; idx < (uint)(1 << treeheight); idx++)
		{
			// Add the next leaf node to the stack.
			gen_leaf(stack + (offset * SPX_N), skseed, pkseed, idx + idxoffset, treeaddr);
			offset++;
			heights[offset - 1] = 0;

			// If this is a node we need for the auth path..
			if ((leafidx ^ 0x1) == idx)
			{
				memcpy(authpath, stack + ((offset - 1) * SPX_N), SPX_N);
			}

			// While the top-most nodes are of equal height..
			while (offset >= 2 && heights[offset - 1] == heights[offset - 2])
			{
				// Compute index of the new node, in the next layer.
				treeidx = (idx >> (heights[offset - 1] + 1));

				// Set the address of the node we're creating.
				SphincsUtils::set_tree_height(treeaddr, heights[offset - 1] + 1);
				SphincsUtils::set_tree_index(treeaddr, treeidx + (idxoffset >> (heights[offset - 1] + 1)));
				// Hash the top-most nodes from the stack together.
				thash(stack + ((offset - 2) * SPX_N), stack + ((offset - 2) * SPX_N), 2, pkseed, treeaddr, buf, mask);
				offset--;
				// Note that the top-most node is now one layer higher.
				heights[offset - 1]++;

				// If this is a node we need for the auth path..
				if (((leafidx >> heights[offset - 1]) ^ 0x1) == treeidx)
				{
					memcpy(authpath + (heights[offset - 1] * SPX_N), stack + ((offset - 1) * SPX_N), SPX_N);
				}
			}
		}

		memcpy(root, stack, SPX_N);
	}

	static void wots_checksum(int32_t* csumbasew, const int32_t* msgbasew)
	{
		uint8_t csumbytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
		int32_t csum;
		uint i;

		csum = 0;

		// Compute checksum.
		for (i = 0; i < SPX_WOTS_LEN1; ++i)
		{
			csum += (SPX_WOTS_W - 1) - msgbasew[i];
		}

		// Convert checksum to base_w.
		// Make sure expected empty zero bits are the least significant bits.
		csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
		SphincsUtils::ull_to_bytes(csumbytes, sizeof(csumbytes), csum);
		base_w(csumbasew, SPX_WOTS_LEN2, csumbytes);
	}

	 // Computes the leaf at a given address. First generates the WOTS key pair,
	 // then computes leaf by hashing horizontally.
	static void wots_gen_leaf(uint8_t* leaf, const uint8_t* skseed, const uint8_t* pkseed, uint addridx, const uint treeaddr[8])
	{
		// Computes the leaf at a given address. First generates the WOTS key pair,
		//   then computes leaf by hashing horizontally.

		uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N];
		uint8_t mask[SPX_WOTS_LEN * SPX_N];
		uint8_t pk[SPX_WOTS_BYTES];
		uint wotsaddr[8] = { 0 };
		uint wotspkaddr[8] = { 0 };

		SphincsUtils::set_type(wotsaddr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::set_type(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);

		SphincsUtils::copy_subtree_addr(wotsaddr, treeaddr);
		SphincsUtils::set_keypair_addr(wotsaddr, addridx);
		wots_gen_pk(pk, skseed, pkseed, wotsaddr);

		SphincsUtils::copy_keypair_addr(wotspkaddr, wotsaddr);
		thash(leaf, pk, SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask);
	}

	 // WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
	 // elements and computes the corresponding public key.
	  // It requires the seed pub_seed (used to generate bitmasks and hash keys)
	 // and the address of this WOTS key pair.
	 //
	 // Writes the computed public key to 'pk'.
	static void wots_gen_pk(uint8_t* pk, const uint8_t* skseed, const uint8_t* pkseed, uint addr[8])
	{
		uint i;

		for (i = 0; i < SPX_WOTS_LEN; ++i)
		{
			SphincsUtils::set_chain_addr(addr, i);
			wots_gen_sk(pk + (i * SPX_N), skseed, addr);
			gen_chain(pk + (i * SPX_N), pk + (i * SPX_N), 0, SPX_WOTS_W - 1, pkseed, addr);
		}
	}

	 // Computes the starting value for a chain, i.e. the secret key.
	 // Expects the address to be complete up to the chain address.
	static void wots_gen_sk(uint8_t* sk, const uint8_t* skseed, uint wotsaddr[8])
	{
		/// Make sure that the hash address is actually zeroed.
		SphincsUtils::set_hash_addr(wotsaddr, 0);
		// Generate sk element.
		prf_addr(sk, skseed, wotsaddr);
	}

	 // Takes a WOTS signature and an n-byte message, computes a WOTS public key.
	 // Writes the computed public key to 'pk'.
	static void wots_pk_from_sig(uint8_t* pk, const uint8_t* signature, const uint8_t* message, const uint8_t* pkseed, uint addr[8])
	{
		int lengths[SPX_WOTS_LEN];
		uint i;

		chain_lengths(lengths, message);

		for (i = 0; i < SPX_WOTS_LEN; ++i)
		{
			SphincsUtils::set_chain_addr(addr, i);
			gen_chain(pk + (i * SPX_N), signature + (i * SPX_N), lengths[i], (SPX_WOTS_W - 1) - lengths[i], pkseed, addr);
		}
	}

	 // Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'.
	static void wots_sign(uint8_t* signature, const uint8_t* message, const uint8_t* skseed, const uint8_t* pkseed, uint addr[8])
	{
		int32_t lengths[SPX_WOTS_LEN];
		uint i;

		chain_lengths(lengths, message);

		for (i = 0; i < SPX_WOTS_LEN; ++i)
		{
			SphincsUtils::set_chain_addr(addr, i);
			wots_gen_sk(signature + (i * SPX_N), skseed, addr);
			gen_chain(signature + (i * SPX_N), signature + (i * SPX_N), 0, lengths[i], pkseed, addr);
		}
	}

	int sphincs_generate(uint8_t* pk, uint8_t* sk)
	{
		// Generates an SPX key pair.
		//   Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
		//   Format pk: [PUB_SEED || root]

		// We do not need the auth path in key generation, but it simplifies the
		//   code to have just one treehash routine that computes both root and path
		//   in one function.

		uint8_t authpath[SPX_TREE_HEIGHT * SPX_N];
		uint heights[SPX_TREE_HEIGHT + 1];
		uint8_t stack[(SPX_TREE_HEIGHT + 1) * SPX_N];
		uint toptreeaddr[8] = { 0 };

		SphincsUtils::set_layer_addr(toptreeaddr, SPX_D - 1);
		SphincsUtils::set_type(toptreeaddr, SPX_ADDR_TYPE_HASHTREE);

		// Initialize SK_SEED, SK_PRF and PUB_SEED.
		if (gen_random(sk, 3 * SPX_N) != 1)
		{
			return 0;
		}

		memcpy(pk, sk + 2 * SPX_N, SPX_N);

		// This hook allows the hash function instantiation to do whatever
		//   preparation or computation it needs, based on the public seed.
		initialize_hash_function(pk, sk);

		// Compute root node of the top-most subtree.
		treehash(sk + (3 * SPX_N), authpath, sk, sk + (2 * SPX_N), 0, 0, SPX_TREE_HEIGHT, toptreeaddr, stack, heights, wots_gen_leaf);
		memcpy(pk + SPX_N, sk + (3 * SPX_N), SPX_N);

		return 1;
	}

	int sphincs_sign(uint8_t* sm, ulong* smlen, const uint8_t* m, ulong mlen, const uint8_t* sk)
	{
		// Returns an array containing the signature followed by the message.
		const uint8_t* pk = sk + (2 * SPX_N);
		const uint8_t* pkseed = pk;
		const uint8_t* skprf = sk + SPX_N;
		const uint8_t* skseed = sk;
		uint heights[SPX_FORS_HEIGHT + 1];
		uint8_t mhash[SPX_FORS_MSG_BYTES];
		uint8_t optrand[SPX_N];
		uint8_t root[SPX_N];
		uint8_t stack[(SPX_FORS_HEIGHT + 1) * SPX_N];
		uint treeaddr[8] = { 0 };
		uint wotsaddr[8] = { 0 };
		ulong i;
		uint idxleaf;
		ulong tree;

		// This hook allows the hash function instantiation to do whatever
		//   preparation or computation it needs, based on the public seed.
		initialize_hash_function(pkseed, skseed);

		SphincsUtils::set_type(wotsaddr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::set_type(treeaddr, SPX_ADDR_TYPE_HASHTREE);

		// Already put the message in the right place, to make it easier to prepend
		//   things when computing the hash over the message.
		   // We need to do this from back to front, so that it works when sm = m
		for (i = mlen; i > 0; i--)
		{
			sm[SPX_BYTES + i - 1] = m[i - 1];
		}
		*smlen = SPX_BYTES + mlen;

		// Optionally, signing can be made non-deterministic using optrand.
		//   This can help counter side-channel attacks that would benefit from
		 //  getting a large number of traces when the signer uses the same nodes.
		if (gen_random(optrand, SPX_N) != 1)
		{
			return 0;
		}
		memset(optrand, 0, sizeof(optrand));
		// Compute the digest randomization value.
		gen_message_random(sm, skprf, optrand, sm + SPX_BYTES, mlen);

		// Derive the message digest and leaf index from R, PK and M.
		hash_message(mhash, &tree, &idxleaf, sm, pk, sm + SPX_BYTES, mlen);
		sm += SPX_N;

		SphincsUtils::set_tree_addr(wotsaddr, tree);
		SphincsUtils::set_keypair_addr(wotsaddr, idxleaf);

		// Sign the message hash using FORS.
		fors_sign(sm, root, mhash, skseed, pkseed, wotsaddr);
		sm += SPX_FORS_BYTES;

		for (i = 0; i < SPX_D; i++)
		{
			SphincsUtils::set_layer_addr(treeaddr, i);
			SphincsUtils::set_tree_addr(treeaddr, tree);

			SphincsUtils::copy_subtree_addr(wotsaddr, treeaddr);
			SphincsUtils::set_keypair_addr(wotsaddr, idxleaf);

			// Compute a WOTS signature.
			wots_sign(sm, root, skseed, pkseed, wotsaddr);
			sm += SPX_WOTS_BYTES;

			// Compute the authentication path for the used WOTS leaf.
			treehash(root, sm, skseed, pkseed, idxleaf, 0, SPX_TREE_HEIGHT, treeaddr, stack, heights, wots_gen_leaf);
			sm += SPX_TREE_HEIGHT * SPX_N;

			// Update the indices for the next layer.
			idxleaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
			tree = tree >> SPX_TREE_HEIGHT;
		}

		return 1;
	}

	int sphincs_verify(uint8_t* m, ulong* mlen, const uint8_t* sm, ulong smlen, const uint8_t* pk)
	{
		// Verifies a given signature-message pair under a given public key.

		const uint8_t* pkroot = pk + SPX_N;
		const uint8_t* pkseed = pk;
		uint8_t buf[SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N];
		uint8_t leaf[SPX_N];
		uint8_t mask[SPX_WOTS_LEN * SPX_N];
		uint8_t mhash[SPX_FORS_MSG_BYTES];
		uint8_t root[SPX_N];
		uint8_t sig[SPX_BYTES];
		uint8_t* sigptr = sig;
		uint treeaddr[8] = { 0 };
		uint wotsaddr[8] = { 0 };
		uint8_t wotspk[SPX_WOTS_BYTES];
		uint wotspkaddr[8] = { 0 };
		ulong tree;
		uint i;
		uint idxleaf;

		// This hook allows the hash function instantiation to do whatever
		//   preparation or computation it needs, based on the public seed.
		initialize_hash_function(pkseed, NULL);
		SphincsUtils::set_type(wotsaddr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::set_type(treeaddr, SPX_ADDR_TYPE_HASHTREE);
		SphincsUtils::set_type(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);

		// The API caller does not necessarily know what size a signature should be
		//   but SPHINCS+ signatures are always exactly SPX_BYTES.
		if (smlen < SPX_BYTES)
		{
			memset(m, 0, smlen);
			*mlen = 0;

			return 0;
		}

		*mlen = smlen - SPX_BYTES;

		// Put the message all the way at the end of the m buffer, so that we can
		// prepend the required other inputs for the hash function.
		memcpy(m + SPX_BYTES, sm + SPX_BYTES, *mlen);

		// Create a copy of the signature so that m = sm is not an issue
		memcpy(sig, sm, SPX_BYTES);

		// Derive the message digest and leaf index from R || PK || M.
		// The additional SPX_N is a result of the hash domain separator.
		hash_message(mhash, &tree, &idxleaf, sigptr, pk, m + SPX_BYTES, *mlen);
		sigptr += SPX_N;

		// Layer correctly defaults to 0, so no need to set_layer_addr
		SphincsUtils::set_tree_addr(wotsaddr, tree);
		SphincsUtils::set_keypair_addr(wotsaddr, idxleaf);

		fors_pk_from_sig(root, sigptr, mhash, pkseed, wotsaddr);
		sigptr += SPX_FORS_BYTES;

		// For each subtree..
		for (i = 0; i < SPX_D; i++)
		{
			SphincsUtils::set_layer_addr(treeaddr, i);
			SphincsUtils::set_tree_addr(treeaddr, tree);
			SphincsUtils::copy_subtree_addr(wotsaddr, treeaddr);
			SphincsUtils::set_keypair_addr(wotsaddr, idxleaf);
			SphincsUtils::copy_keypair_addr(wotspkaddr, wotsaddr);

			// The WOTS public key is only correct if the signature was correct.
			// Initially, root is the FORS pk, but on subsequent iterations it is
			//  the root of the subtree below the currently processed subtree.
			wots_pk_from_sig(wotspk, sigptr, root, pkseed, wotsaddr);
			sigptr += SPX_WOTS_BYTES;

			// Compute the leaf node using the WOTS public key.
			thash(leaf, wotspk, SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask);

			// Compute the root node of this subtree.
			compute_root(root, leaf, idxleaf, 0, sigptr, SPX_TREE_HEIGHT, pkseed, treeaddr);
			sigptr += SPX_TREE_HEIGHT * SPX_N;

			// Update the indices for the next layer.
			idxleaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
			tree = tree >> SPX_TREE_HEIGHT;
		}

		// Check if the root node equals the root node in the public key.
		if (memcmp(root, pkroot, SPX_N))
		{
			// If not, zero the message
			memset(m, 0, smlen);
			*mlen = 0;

			return 2;
		}

		// If verification was successful, move the message to the right place.
		memmove(m, m + SPX_BYTES, *mlen);

		return 1;
	}

*/