// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_SPHINCSBASE_H
#define CEX_SPHINCSBASE_H

#include "CexDomain.h"
#include "IntegerTools.h"
#include "IPrng.h"
#include "Keccak.h"
#include "MemoryTools.h"

/// 
/// internal
/// 

NAMESPACE_SPHINCSPLUS

using Digest::Keccak;
using Prng::IPrng;
using Tools::IntegerTools;
using Tools::MemoryTools;

/// <summary>
// The internal SphincsPlus base class
/// </summary>
class SPXBase
{
public:
	
	/// <summary>
	/// The SPHINCS+ S1P128 SHAKE parameter set
	/// </summary>
	class ParamsS1P128
	{
	public:

		static const size_t SPX_PUBLICKEY_SIZE = 32;
		static const size_t SPX_SECRETKEY_SIZE = 64;
		static const size_t SPX_SIGNATURE_SIZE = 7856;
		static const uint32_t SPX_N = 16;
		static const uint32_t SPX_FULL_HEIGHT = 63;
		static const uint32_t SPX_D = 7;
		static const uint32_t SPX_FORS_HEIGHT = 12;
		static const uint32_t SPX_FORS_TREES = 14;
		static const uint32_t SPX_WOTS_W = 16;
		static const uint32_t SPX_WOTS_LOGW = 4;
		static const uint32_t SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
		static const uint32_t SPX_WOTS_LEN2 = 3;
		static const uint32_t SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
		static const uint32_t SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
		static const uint32_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
		static const uint32_t SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
		static const uint32_t SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
		static const uint32_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
		static const size_t PRF_RATE_SIZE = Keccak::KECCAK256_RATE_SIZE;
	};
			
	/// <summary>
	/// The SPHINCS+ S1P192 SHAKE parameter set
	/// </summary>
	class ParamsS3P192
	{
	public:

		static const size_t SPX_PUBLICKEY_SIZE = 48;
		static const size_t SPX_SECRETKEY_SIZE = 96;
		static const size_t SPX_SIGNATURE_SIZE = 16224;
		static const uint32_t SPX_N = 24;
		static const uint32_t SPX_FULL_HEIGHT = 63;
		static const uint32_t SPX_D = 7;
		static const uint32_t SPX_FORS_HEIGHT = 14;
		static const uint32_t SPX_FORS_TREES = 17;
		static const uint32_t SPX_WOTS_W = 16;
		static const uint32_t SPX_WOTS_LOGW = 4;
		static const uint32_t SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
		static const uint32_t SPX_WOTS_LEN2 = 3;
		static const uint32_t SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
		static const uint32_t SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
		static const uint32_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
		static const uint32_t SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
		static const uint32_t SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
		static const uint32_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
		static const size_t PRF_RATE_SIZE = Keccak::KECCAK256_RATE_SIZE;
	};
		
	/// <summary>
	/// The SPHINCS+ S5P256 SHAKE parameter set
	/// </summary>
	class ParamsS5P256
	{
	public:

		static const size_t SPX_PUBLICKEY_SIZE = 64;
		static const size_t SPX_SECRETKEY_SIZE = 128;
		static const size_t SPX_SIGNATURE_SIZE = 29792;
		static const size_t SPX_N = 32;
		static const size_t SPX_FULL_HEIGHT = 64;
		static const size_t SPX_D = 8;
		static const size_t SPX_FORS_HEIGHT = 14;
		static const size_t SPX_FORS_TREES = 22;
		static const size_t SPX_WOTS_W = 16;
		static const size_t SPX_WOTS_LOGW = 4;
		static const size_t SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
		static const size_t SPX_WOTS_LEN2 = 3;
		static const size_t SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
		static const size_t SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
		static const size_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
		static const size_t SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
		static const size_t SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
		static const size_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
		static const size_t PRF_RATE_SIZE = Keccak::KECCAK256_RATE_SIZE;
	};
			
	/// <summary>
	/// The SPHINCS+ S5P512 SHAKE parameter set
	/// </summary>
	class ParamsS6P512
	{
	public:

		static const size_t SPX_PUBLICKEY_SIZE = 128;
		static const size_t SPX_SECRETKEY_SIZE = 256;
		static const size_t SPX_SIGNATURE_SIZE = 100032;
		static const size_t SPX_N = 64;
		static const size_t SPX_FULL_HEIGHT = 64;
		static const size_t SPX_D = 8;
		static const size_t SPX_FORS_HEIGHT = 14;
		static const size_t SPX_FORS_TREES = 30;
		static const size_t SPX_WOTS_W = 16;
		static const size_t SPX_WOTS_LOGW = 4;
		static const size_t SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
		static const size_t SPX_WOTS_LEN2 = 3;
		static const size_t SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
		static const size_t SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
		static const size_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
		static const size_t SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
		static const size_t SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
		static const size_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
		static const size_t PRF_RATE_SIZE = Keccak::KECCAK512_RATE_SIZE;
	};

private:

	static const uint32_t SPX_ADDR_TYPE_WOTS = 0;
	static const uint32_t SPX_ADDR_TYPE_WOTSPK = 1;
	static const uint32_t SPX_ADDR_TYPE_HASHTREE = 2;
	static const size_t SPX_ADDR_TYPE_FORSTREE = 3;
	static const size_t SPX_ADDR_TYPE_FORSPK = 4;
	static const size_t SPX_ADDR_BYTES = 32;
	static const uint32_t SPX_OFFSET_TREE = 8;
	static const uint32_t SPX_OFFSET_KP_ADDR2 = 22;
	static const uint32_t SPX_OFFSET_KP_ADDR1 = 23;

	// Utils

	static void CopyKeypairAddress(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output);

	static void CopySubtreeAddress(const std::array<uint32_t, 8> &Input, std::array<uint32_t, 8> &Output);

	static void SetChainAddress(std::array<uint32_t, 8> &Address, uint32_t Chain);

	static void SetHashAddress(std::array<uint32_t, 8> &Address, uint32_t Hash);

	static void SetKeypairAddress(std::array<uint32_t, 8> &Address, uint32_t Keypair);

	static void SetLayerAddress(std::array<uint32_t, 8> &Address, uint32_t Layer);

	static void SetTreeAddress(std::array<uint32_t, 8> &Address, uint64_t Tree);

	static void SetTreeHeight(std::array<uint32_t, 8> &Address, uint32_t TreeHeight);

	static void SetTreeIndex(std::array<uint32_t, 8> &Address, uint32_t TreeIndex);

	static void SetType(std::array<uint32_t, 8> &Address, uint32_t Type);

	static void UllToBytes(std::vector<uint8_t> &Output, size_t Offset, uint64_t Value, size_t Length);

	static void AddressToBytes(std::vector<uint8_t> &Output, size_t Offset, const std::array<uint32_t, 8> &Address);

	static uint64_t BytesToUll(const std::vector<uint8_t> &Input, size_t Offset, size_t Length);

	static void PrfAddress(std::vector<uint8_t> &Output, size_t Offset, const std::vector<uint8_t> &Key, const std::array<uint32_t, 8> &Address, size_t N);

	static void XOF(const std::vector<uint8_t> &Input, size_t InOffset, size_t InLength, std::vector<uint8_t> &Output, size_t OutOffset, size_t OutLength, size_t Rate);

	template<typename T>
	static void THash(T &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const size_t InputBlocks,
		const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, std::vector<uint8_t> &Buffer, std::vector<uint8_t> &Mask)
	{
		size_t i;

		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(Mask, 0, Mask.size());
		MemoryTools::Copy(PkSeed, 0, Buffer, 0, Params.SPX_N);
		AddressToBytes(Buffer, Params.SPX_N, Address);

		std::vector<uint8_t> k(Params.SPX_N + SPX_ADDR_BYTES);
		MemoryTools::Copy(Buffer, 0, k, 0, k.size());

		XOF(k, 0, k.size(), Mask, 0, InputBlocks * Params.SPX_N, Params.PRF_RATE_SIZE);

		for (i = 0; i < InputBlocks * Params.SPX_N; ++i)
		{
			Buffer[Params.SPX_N + SPX_ADDR_BYTES + i] = Input[InOffset + i] ^ Mask[i];
		}

		k.resize(Params.SPX_N + SPX_ADDR_BYTES + InputBlocks * Params.SPX_N);
		MemoryTools::Copy(Buffer, 0, k, 0, k.size());

		XOF(k, 0, k.size(), Output, OutOffset, Params.SPX_N, Params.PRF_RATE_SIZE);
	}

	// FORS

	template<typename T>
	static void ComputeRoot(T &Params, std::vector<uint8_t> &Root, size_t RootOffset, const std::vector<uint8_t> &Leaf, uint32_t LeafOffset, uint32_t IdxOffset, const std::vector<uint8_t> &AuthPath,
		size_t AuthOffset, uint32_t TreeHeight, const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address)
	{
		// computes a Root node given a Leaf and an auth path.
		// expects Addressess to be complete other than the tree_height and tree_index
		std::vector<uint8_t> buf1(Params.SPX_N * 2);
		std::vector<uint8_t> buf2(Params.SPX_N + SPX_ADDR_BYTES + (Params.SPX_N * 2));
		std::vector<uint8_t> mask(Params.SPX_N * 2);
		uint32_t idx;

		// if LeafOffset is odd (last bit = 1), current path element is a right child
		// and AuthPath has to go left, otherwise it is the other way around
		if ((LeafOffset & 1) == 1)
		{
			MemoryTools::Copy(Leaf, 0, buf1, Params.SPX_N, Params.SPX_N);
			MemoryTools::Copy(AuthPath, AuthOffset, buf1, 0, Params.SPX_N);
		}
		else
		{
			MemoryTools::Copy(Leaf, 0, buf1, 0, Params.SPX_N);
			MemoryTools::Copy(AuthPath, AuthOffset, buf1, Params.SPX_N, Params.SPX_N);
		}

		AuthOffset += Params.SPX_N;

		for (idx = 0; idx < TreeHeight - 1; ++idx)
		{
			LeafOffset >>= 1;
			IdxOffset >>= 1;

			// set the Addressess of the node we're creating
			SetTreeHeight(Address, idx + 1);
			SetTreeIndex(Address, LeafOffset + IdxOffset);

			// pick the right or left neighbor, depending on parity of the node
			if (LeafOffset & 1)
			{
				THash(Params, buf1, Params.SPX_N, buf1, 0, 2, PkSeed, Address, buf2, mask);
				MemoryTools::Copy(AuthPath, AuthOffset, buf1, 0, Params.SPX_N);
			}
			else
			{
				THash(Params, buf1, 0, buf1, 0, 2, PkSeed, Address, buf2, mask);
				MemoryTools::Copy(AuthPath, AuthOffset, buf1, Params.SPX_N, Params.SPX_N);
			}

			AuthOffset += Params.SPX_N;
		}

		// the last iteration is exceptional; we do not copy an AuthPath node
		LeafOffset >>= 1;
		IdxOffset >>= 1;
		SetTreeHeight(Address, TreeHeight);
		SetTreeIndex(Address, LeafOffset + IdxOffset);
		THash(Params, Root, RootOffset, buf1, 0, 2, PkSeed, Address, buf2, mask);
	}

	template<typename T>
	static void ForsGenLeaf(T &Params, std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SecretSeed, const std::vector<uint8_t> &PublicSeed, 
		uint32_t AddressIdx, const std::array<uint32_t, 8> &TreeAddress)
	{
		std::array<uint32_t, 8> leafaddress = { 0 };

		// only copy the parts that must be kept in fors_leaf_addr
		CopyKeypairAddress(TreeAddress, leafaddress);
		SetType(leafaddress, SPX_ADDR_TYPE_FORSTREE);
		SetTreeIndex(leafaddress, AddressIdx);
		ForsGenSk(Params, Leaf, LeafOffset, SecretSeed, leafaddress);
		ForsSkToLeaf(Params, Leaf, Leaf, LeafOffset, PublicSeed, leafaddress);
	}

	template<typename T>
	static void ForsGenSk(T &Params, std::vector<uint8_t> &Secret, size_t SecretOffset, const std::vector<uint8_t> &Seed, std::array<uint32_t, 8> &Address)
	{
		PrfAddress(Secret, SecretOffset, Seed, Address, Params.SPX_N);
	}

	template<typename T>
	static void ForsPkFromSig(T &Params, std::vector<uint8_t> &PublicKey, size_t PubKeyOffset, const std::vector<uint8_t> &Signature, size_t SigOffset, 
		const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PublicSeed, const std::array<uint32_t, 8> &ForsAddress)
	{
		std::array<uint32_t, 8> forstreeaddr = { 0 };
		std::array<uint32_t, 8> forspkaddr = { 0 };
		std::vector<uint32_t> indices(Params.SPX_FORS_TREES * Params.SPX_N);
		std::vector<uint8_t> leaf(Params.SPX_N);
		std::vector<uint8_t> roots(Params.SPX_FORS_TREES * Params.SPX_N);
		uint32_t idx;
		uint32_t idxsig;
		uint32_t idxoff;

		idxsig = static_cast<uint32_t>(SigOffset);
		CopyKeypairAddress(ForsAddress, forstreeaddr);
		CopyKeypairAddress(ForsAddress, forspkaddr);
		SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
		SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);

		MessageToIndices(Params, indices, Message);

		for (idx = 0; idx < Params.SPX_FORS_TREES; ++idx)
		{
			idxoff = idx * (1 << Params.SPX_FORS_HEIGHT);
			SetTreeHeight(forstreeaddr, 0);
			SetTreeIndex(forstreeaddr, indices[idx] + idxoff);
			// derive the leaf from the included secret key part
			ForsSkToLeaf(Params, leaf, Signature, idxsig, PublicSeed, forstreeaddr);
			idxsig += static_cast<uint32_t>(Params.SPX_N);
			// derive the corresponding root node of this tree
			ComputeRoot(Params, roots, Params.SPX_N * idx, leaf, indices[idx], idxoff, Signature, idxsig, Params.SPX_FORS_HEIGHT, PublicSeed, forstreeaddr);
			idxsig += static_cast<uint32_t>(Params.SPX_N) * Params.SPX_FORS_HEIGHT;
		}

		// hash horizontally across all tree roots to derive the public key
		std::vector<uint8_t> buf(Params.SPX_N + SPX_ADDR_BYTES + Params.SPX_FORS_TREES * Params.SPX_N);
		std::vector<uint8_t> mask(Params.SPX_FORS_TREES * Params.SPX_N);
		THash(Params, PublicKey, PubKeyOffset, roots, 0, Params.SPX_FORS_TREES, PublicSeed, forspkaddr, buf, mask);
	}

	template<typename T>
	static void ForsSign(T &Params, std::vector<uint8_t> &Signature, size_t SigOffset, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Message,
		const std::vector<uint8_t> &SecretSeed, const std::vector<uint8_t> &PublicSeed, const std::array<uint32_t, 8> &ForsAddress)
	{
		std::array<uint32_t, 8> forstreeaddr = { 0 };
		std::array<uint32_t, 8> forspkaddr = { 0 };
		std::vector<uint32_t> heights(Params.SPX_FORS_HEIGHT + 1);
		std::vector<uint32_t> indices(Params.SPX_FORS_TREES);
		std::vector<uint8_t> roots(Params.SPX_FORS_TREES * Params.SPX_N);
		std::vector<uint8_t> stack((Params.SPX_FORS_HEIGHT + 1) * Params.SPX_N);
		size_t idxsm;
		size_t idx;
		size_t idxoff;

		idxsm = SigOffset;

		CopyKeypairAddress(ForsAddress, forstreeaddr);
		CopyKeypairAddress(ForsAddress, forspkaddr);
		SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
		SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);
		MessageToIndices(Params, indices, Message);

		for (idx = 0; idx < Params.SPX_FORS_TREES; ++idx)
		{
			idxoff = idx * (1ULL << Params.SPX_FORS_HEIGHT);
			SetTreeHeight(forstreeaddr, 0);
			SetTreeIndex(forstreeaddr, indices[idx] + static_cast<uint32_t>(idxoff));
			// include the secret key part that produces the selected leaf node
			ForsGenSk(Params, Signature, idxsm, SecretSeed, forstreeaddr);
			idxsm += Params.SPX_N;
			// compute the authentication path for this leaf node
			ForsTreeHash(Params, roots, Params.SPX_N * idx, Signature, idxsm, SecretSeed, PublicSeed, indices[idx], static_cast<uint32_t>(idxoff), forstreeaddr, stack, heights);
			idxsm += Params.SPX_N * Params.SPX_FORS_HEIGHT;
		}

		// hash horizontally across all tree roots to derive the public key
		std::vector<uint8_t> buf(Params.SPX_N + SPX_ADDR_BYTES + (Params.SPX_FORS_TREES * Params.SPX_N));
		std::vector<uint8_t> mask(Params.SPX_FORS_TREES * Params.SPX_N);
		THash(Params, PublicKey, 0, roots, 0, Params.SPX_FORS_TREES, PublicSeed, forspkaddr, buf, mask);
	}

	template<typename T>
	static void ForsSkToLeaf(T &Params, std::vector<uint8_t> &Leaf, const std::vector<uint8_t> &SecretKey, size_t KeyOffset, const std::vector<uint8_t> &PublicSeed, std::array<uint32_t, 8> &LeafAddress)
	{
		std::vector<uint8_t> buf(Params.SPX_N + SPX_ADDR_BYTES + 1 * Params.SPX_N);
		std::vector<uint8_t> mask(Params.SPX_N);

		THash(Params, Leaf, 0, SecretKey, KeyOffset, 1, PublicSeed, LeafAddress, buf, mask);
	}

	template<typename T>
	static void GenMessageRandom(T &Params, const std::vector<uint8_t> &SkPrf, const std::vector<uint8_t> &OptRnd, std::vector<uint8_t> &Message, size_t MsgLength)
	{
		MemoryTools::Copy(SkPrf, 0, Message, Params.SPX_BYTES - (2 * Params.SPX_N), Params.SPX_N);
		MemoryTools::Copy(OptRnd, 0, Message, Params.SPX_BYTES - Params.SPX_N, Params.SPX_N);

		std::vector<uint8_t> k(MsgLength + (2 * Params.SPX_N));
		MemoryTools::Copy(Message, Params.SPX_BYTES - (2 * Params.SPX_N), k, 0, k.size());

		XOF(k, 0, k.size(), Message, 0, Params.SPX_N, Params.PRF_RATE_SIZE);
	}

	template<typename T>
	static void HashMessage(T &Params, std::vector<uint8_t> &Digest, uint64_t &Tree, uint32_t &LeafIndex, const std::vector<uint8_t> &Rand, const std::vector<uint8_t> &PublicKey,
		std::vector<uint8_t> &Message, size_t MsgLength)
	{
		const size_t FORSMSG = ((Params.SPX_FORS_HEIGHT * Params.SPX_FORS_TREES + 7) / 8);
		const size_t TREEBITS = (Params.SPX_TREE_HEIGHT * (Params.SPX_D - 1));
		const size_t TREEBYTES = ((TREEBITS + 7) / 8);
		const size_t LEAFBITS = Params.SPX_TREE_HEIGHT;
		const size_t LEAFBYTES = ((LEAFBITS + 7) / 8);
		const size_t DGSTBYTES = (FORSMSG + TREEBYTES + LEAFBYTES);
		const size_t PKBYTES = (2 * Params.SPX_N);//Params.SPX_BYTES, Message.size(), Params.SPX_FORS_HEIGHT, Params.SPX_FORS_TREES, Params.SPX_N
		std::vector<uint8_t> buf(DGSTBYTES);

		MemoryTools::Copy(Rand, 0, Message, Params.SPX_BYTES - Params.SPX_N - PKBYTES, Params.SPX_N);
		MemoryTools::Copy(PublicKey, 0, Message, Params.SPX_BYTES - PKBYTES, PKBYTES);

		std::vector<uint8_t> k(MsgLength + Params.SPX_N + PKBYTES);
		MemoryTools::Copy(Message, Params.SPX_BYTES - Params.SPX_N - PKBYTES, k, 0, k.size());

		XOF(k, 0, k.size(), buf, 0, DGSTBYTES, Params.PRF_RATE_SIZE);

		MemoryTools::Copy(buf, 0, Digest, 0, FORSMSG);
		Tree = BytesToUll(buf, FORSMSG, TREEBYTES);
		Tree &= (~0ULL) >> (64 - TREEBITS);
		LeafIndex = BytesToUll(buf, FORSMSG + TREEBYTES, LEAFBYTES);
		LeafIndex &= (~0UL) >> (32 - LEAFBITS);
	}

	template<typename T>
	static void MessageToIndices(T &Params, std::vector<uint32_t> &Indices, const std::vector<uint8_t> &Messages)
	{
		// Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
		// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
		// Assumes indices has space for SPX_FORS_TREES integers. 
		
		size_t i;
		size_t j;
		size_t oft;

		oft = 0;

		for (i = 0; i < Params.SPX_FORS_TREES; ++i)
		{
			Indices[i] = 0;

			for (j = 0; j < Params.SPX_FORS_HEIGHT; ++j)
			{
				Indices[i] ^= ((Messages[oft >> 3] >> (oft & 0x07)) & 0x01) << j;
				++oft;
			}
		}
	}

	// WOTS

	template<typename T>
	static void BaseW(T &Params, std::vector<int32_t> &Output, size_t OutOffset, size_t OutLength, const std::vector<uint8_t> &Input)
	{
		// base_w algorithm as described in draft
		// interprets an array of bytes as integers in base w
		// this only works when log_w is a divisor of 8

		size_t i;
		size_t inoff;
		int32_t bits;
		uint8_t total;

		bits = 0;
		inoff = 0;
		total = 0;

		for (i = 0; i < OutLength; ++i)
		{
			if (bits == 0)
			{
				total = Input[inoff];
				++inoff;
				bits += 8;
			}

			bits -= Params.SPX_WOTS_LOGW;
			Output[OutOffset] = (total >> bits) & (Params.SPX_WOTS_W - 1);
			++OutOffset;
		}
	}

	template<typename T>
	static void ChainLengths(T &Params, std::vector<int32_t> &Lengths, const std::vector<uint8_t> &Message)
	{
		const size_t WOTSLEN1 = (8UL * Params.SPX_N / Params.SPX_WOTS_LOGW);
		// takes a message and derives the matching chain lengths
		BaseW(Params, Lengths, 0, WOTSLEN1, Message);
		WotsChecksum(Params, Lengths, WOTSLEN1, Lengths);
	}

	template<typename T>
	static void GenChain(T &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, uint32_t Start, uint32_t Steps,
		const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address)
	{
		std::vector<uint8_t> mask(1 * Params.SPX_N);
		uint32_t idx;

		// initialize out with the value at position 'start'
		MemoryTools::Copy(Input, InOffset, Output, OutOffset, Params.SPX_N);

		// iterate 'steps' calls to the hash function
		for (idx = Start; idx < (Start + Steps) && idx < Params.SPX_WOTS_W; ++idx)
		{
			SetHashAddress(Address, idx);
			THash(Params, Output, OutOffset, Output, OutOffset, 1, PkSeed, Address, Params.SPX_N + SPX_ADDR_BYTES + 1 * Params.SPX_N, mask);
		}
	}

	template<typename T>
	static void THash(T &Params, std::vector<uint8_t> &Output, size_t OutOffset, const std::vector<uint8_t> &Input, size_t InOffset, const size_t InputBlocks,
		const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t BufLen, std::vector<uint8_t> &Mask)
	{
		std::vector<uint8_t> buf(BufLen);
		size_t i;

		MemoryTools::Copy(PkSeed, 0, buf, 0, Params.SPX_N);
		AddressToBytes(buf, Params.SPX_N, Address);

		XOF(buf, 0, Params.SPX_N + SPX_ADDR_BYTES, Mask, 0, InputBlocks * Params.SPX_N, Params.PRF_RATE_SIZE);

		for (i = 0; i < InputBlocks * Params.SPX_N; ++i)
		{
			buf[Params.SPX_N + SPX_ADDR_BYTES + i] = Input[InOffset + i] ^ Mask[i];
		}

		XOF(buf, 0, Params.SPX_N + SPX_ADDR_BYTES + InputBlocks * Params.SPX_N, Output, OutOffset, Params.SPX_N, Params.PRF_RATE_SIZE);
	}

	template<typename T>
	static void WotsChecksum(T &Params, std::vector<int32_t> &CSumBaseW, size_t BaseOffset, const std::vector<int32_t> &MsgBaseW)
	{
		// computes the WOTS checksum over a message (in base_w)

		const size_t WOTSLEN1 = (8UL * Params.SPX_N / Params.SPX_WOTS_LOGW);
		std::vector<uint8_t> csumbytes((Params.SPX_WOTS_LEN2 * Params.SPX_WOTS_LOGW + 7) / 8);
		uint64_t csum;
		uint32_t idx;

		csum = 0;

		// compute checksum
		for (idx = 0; idx < WOTSLEN1; ++idx)
		{
			csum += static_cast<uint64_t>(Params.SPX_WOTS_W - 1) - MsgBaseW[idx];
		}

		// convert checksum to base_w
		// make sure expected empty zero bits are the least significant bits
		csum = csum << (8 - ((Params.SPX_WOTS_LEN2 * Params.SPX_WOTS_LOGW) % 8));
		UllToBytes(csumbytes, 0, csum, csumbytes.size());
		BaseW(Params, CSumBaseW, BaseOffset, Params.SPX_WOTS_LEN2, csumbytes);
	}

	template<typename T>
	static void WotsGenLeaf(T &Params, std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed, uint32_t AddressIndex,
		const std::array<uint32_t, 8> &TreeAddress)
	{
		const size_t WOTSLEN = ((8UL * Params.SPX_N / Params.SPX_WOTS_LOGW) + Params.SPX_WOTS_LEN2);
		const size_t WOTSBYTES = (WOTSLEN * Params.SPX_N);
		// computes the leaf at a given address
		// first generates the SPXPWOTS key pair, then computes leaf by hashing horizontally
		std::vector<uint8_t> mask(WOTSLEN * Params.SPX_N);
		std::vector<uint8_t> pk(WOTSBYTES);
		std::array<uint32_t, 8> wotsaddr = { 0 };
		std::array<uint32_t, 8> wotspkaddr = { 0 };

		SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
		SetType(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);
		CopySubtreeAddress(TreeAddress, wotsaddr);
		SetKeypairAddress(wotsaddr, AddressIndex);

		WotsGenPk(Params, pk, SkSeed, PkSeed, wotsaddr);
		CopyKeypairAddress(wotsaddr, wotspkaddr);
		THash(Params, Leaf, LeafOffset, pk, 0, WOTSLEN, PkSeed, wotspkaddr, Params.SPX_N + SPX_ADDR_BYTES + WOTSLEN * Params.SPX_N, mask);
	}

	template<typename T>
	static void WotsGenPk(T &Params, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address)
	{
		const size_t WOTSLEN2 = (8UL * Params.SPX_N / Params.SPX_WOTS_LOGW) + Params.SPX_WOTS_LEN2;

		size_t idx;

		for (idx = 0; idx < WOTSLEN2; ++idx)
		{
			SetChainAddress(Address, static_cast<uint32_t>(idx));
			WotsGenSk(Params, PublicKey, idx * Params.SPX_N, SkSeed, Address);
			GenChain(Params, PublicKey, idx * Params.SPX_N, PublicKey, idx * Params.SPX_N, 0, Params.SPX_WOTS_W - 1, PkSeed, Address);
		}
	}

	template<typename T>
	static void WotsGenSk(T &Params, std::vector<uint8_t> &Key, size_t Offset, const std::vector<uint8_t> &KeySeed, std::array<uint32_t, 8> &WotsAddress)
	{
		// make sure that the hash address is actually zeroed
		SetHashAddress(WotsAddress, 0);
		// generate sk element
		PrfAddress(Key, Offset, KeySeed, WotsAddress, Params.SPX_N);
	}

	template<typename T>
	static void WotsPkFromSig(T &Params, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message,
		const std::vector<uint8_t> &PrivateSeed, std::array<uint32_t, 8> &Address)
	{
		const size_t WOTSLEN = ((8UL * Params.SPX_N / Params.SPX_WOTS_LOGW) + Params.SPX_WOTS_LEN2);
		std::vector<int32_t> lengths(WOTSLEN);
		size_t idx;

		ChainLengths(Params, lengths, Message);

		for (idx = 0; idx < WOTSLEN; ++idx)
		{
			SetChainAddress(Address, static_cast<uint32_t>(idx));
			GenChain(Params, PublicKey, idx * Params.SPX_N, Signature, SigOffset + (idx * Params.SPX_N), lengths[idx], (Params.SPX_WOTS_W - 1) - lengths[idx], PrivateSeed, Address);
		}
	}

	template<typename T>
	static void WotsSign(T &Params, std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &SecretSeed,
		const std::vector<uint8_t> &PublicSeed, std::array<uint32_t, 8> &Address)
	{
		const size_t WOTSLEN = ((8UL * Params.SPX_N / Params.SPX_WOTS_LOGW) + Params.SPX_WOTS_LEN2);
		std::vector<int32_t> lengths(WOTSLEN);
		size_t idx;

		ChainLengths(Params, lengths, Message);

		for (idx = 0; idx < WOTSLEN; ++idx)
		{
			SetChainAddress(Address, static_cast<uint32_t>(idx));
			WotsGenSk(Params, Signature, SigOffset + (idx * Params.SPX_N), SecretSeed, Address);
			GenChain(Params, Signature, SigOffset + (idx * Params.SPX_N), Signature, SigOffset + (idx * Params.SPX_N), 0, lengths[idx], PublicSeed, Address);
		}
	}
	
	template<typename T>
	static void ForsTreeHash(T &Params, std::vector<uint8_t> &Root, size_t RootOffset, std::vector<uint8_t> &Authpath, size_t AuthOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed,
		uint32_t LeafIndex, uint32_t IndexOffset, std::array<uint32_t, 8> &TreeAddress, std::vector<uint8_t> &Stack, std::vector<uint32_t> &Heights)
	{
		std::vector<uint8_t> buf(Params.SPX_N + SPX_ADDR_BYTES + 2 * Params.SPX_N);
		std::vector<uint8_t> leaf(Params.SPX_N);
		std::vector<uint8_t> mask(2 * Params.SPX_N);
		size_t offset;
		uint32_t idx;
		uint32_t treeidx;

		offset = 0;

		for (idx = 0; idx < static_cast<uint32_t>(1 << Params.SPX_FORS_HEIGHT); ++idx)
		{
			// add the next (fors or wots) leaf node to the stack
			ForsGenLeaf(Params, leaf, 0, SkSeed, PkSeed, idx + IndexOffset, TreeAddress);
			MemoryTools::Copy(leaf, 0, Stack, offset * Params.SPX_N, Params.SPX_N);
			++offset;
			Heights[offset - 1] = 0;

			// if this is a node we need for the auth path
			if ((LeafIndex ^ 0x1) == idx)
			{
				MemoryTools::Copy(Stack, ((offset - 1) * Params.SPX_N), Authpath, AuthOffset, Params.SPX_N);
			}

			// while the top-most nodes are of equal height
			while (offset >= 2 && Heights[offset - 1] == Heights[offset - 2])
			{
				// compute index of the new node, in the next layer
				treeidx = (idx >> (Heights[offset - 1] + 1));
				// set the address of the node we're creating
				SetTreeHeight(TreeAddress, Heights[offset - 1] + 1);
				SetTreeIndex(TreeAddress, treeidx + (IndexOffset >> (Heights[offset - 1] + 1)));
				// hash the top-most nodes from the stack together
				THash(Params, Stack, ((offset - 2) * Params.SPX_N), Stack, ((offset - 2) * Params.SPX_N), 2, PkSeed, TreeAddress, buf, mask);
				--offset;
				// note that the top-most node is now one layer higher
				++Heights[offset - 1];

				// if this is a node we need for the auth path
				if (((LeafIndex >> Heights[offset - 1]) ^ 0x1) == treeidx)
				{
					MemoryTools::Copy(Stack, (offset - 1) * Params.SPX_N, Authpath, AuthOffset + (Params.SPX_N * Heights[offset - 1]), Params.SPX_N);
				}
			}
		}

		MemoryTools::Copy(Stack, 0, Root, RootOffset, Params.SPX_N);
	}
	
	template<typename T>
	static void WotsTreeHash(T &Params, std::vector<uint8_t> &Root, size_t RootOffset, std::vector<uint8_t> &Authpath, size_t AuthOffset, const std::vector<uint8_t> &SkSeed, const std::vector<uint8_t> &PkSeed,
		uint32_t LeafIndex, uint32_t IndexOffset, std::array<uint32_t, 8> &TreeAddress, std::vector<uint8_t> &Stack, std::vector<uint32_t> &Heights)
	{
		std::vector<uint8_t> buf(Params.SPX_N + SPX_ADDR_BYTES + 2 * Params.SPX_N);
		std::vector<uint8_t> leaf(Params.SPX_N);
		std::vector<uint8_t> mask(2 * Params.SPX_N);
		size_t offset;
		uint32_t idx;
		uint32_t treeidx;

		offset = 0;

		for (idx = 0; idx < static_cast<uint32_t>(1 << Params.SPX_TREE_HEIGHT); ++idx)
		{
			// add the next (fors or wots) leaf node to the stack
			WotsGenLeaf(Params, leaf, 0, SkSeed, PkSeed, idx + IndexOffset, TreeAddress);
			MemoryTools::Copy(leaf, 0, Stack, offset * Params.SPX_N, Params.SPX_N);
			++offset;
			Heights[offset - 1] = 0;

			// if this is a node we need for the auth path
			if ((LeafIndex ^ 0x1) == idx)
			{
				MemoryTools::Copy(Stack, ((offset - 1) * Params.SPX_N), Authpath, AuthOffset, Params.SPX_N);
			}

			// while the top-most nodes are of equal height
			while (offset >= 2 && Heights[offset - 1] == Heights[offset - 2])
			{
				// compute index of the new node, in the next layer
				treeidx = (idx >> (Heights[offset - 1] + 1));
				// set the address of the node we're creating
				SetTreeHeight(TreeAddress, Heights[offset - 1] + 1);
				SetTreeIndex(TreeAddress, treeidx + (IndexOffset >> (Heights[offset - 1] + 1)));
				// hash the top-most nodes from the stack together
				THash(Params, Stack, ((offset - 2) * Params.SPX_N), Stack, ((offset - 2) * Params.SPX_N), 2, PkSeed, TreeAddress, buf, mask);
				--offset;
				// note that the top-most node is now one layer higher
				++Heights[offset - 1];

				// if this is a node we need for the auth path
				if (((LeafIndex >> Heights[offset - 1]) ^ 0x1) == treeidx)
				{
					MemoryTools::Copy(Stack, (offset - 1) * Params.SPX_N, Authpath, AuthOffset + (Params.SPX_N * Heights[offset - 1]), Params.SPX_N);
				}
			}
		}

		MemoryTools::Copy(Stack, 0, Root, RootOffset, Params.SPX_N);
	}

public:

	template<typename T>
	static void Generate(T &Params, std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<IPrng> &Rng)
	{
		std::vector<uint32_t> heights(Params.SPX_TREE_HEIGHT + 1);
		std::vector<uint8_t> stack((Params.SPX_TREE_HEIGHT + 1) * Params.SPX_N);
		std::vector<uint8_t> authpath(Params.SPX_TREE_HEIGHT * Params.SPX_N);
		std::vector<uint8_t> root(Params.SPX_N);
		std::vector<uint8_t> pkseed(Params.SPX_N);
		std::vector<uint8_t> skseed(Params.SPX_N);
		std::vector<uint8_t> stmp(3 * Params.SPX_N);
		std::array<uint32_t, 8> toptreeaddr = { 0 };

		SetLayerAddress(toptreeaddr, Params.SPX_D - 1);
		SetType(toptreeaddr, SPX_ADDR_TYPE_HASHTREE);

		// generate the seed buffer
		Rng->Generate(stmp, 0, stmp.size());
		// copy to private and public keys
		MemoryTools::Copy(stmp, 0, PrivateKey, 0, stmp.size());
		MemoryTools::Copy(stmp, (2 * Params.SPX_N), PublicKey, 0, Params.SPX_N);
		// seeds for the hashing function
		MemoryTools::Copy(stmp, 0, skseed, 0, Params.SPX_N);
		MemoryTools::Copy(stmp, 2 * Params.SPX_N, pkseed, 0, Params.SPX_N);

		// compute root node of the top-most subtree, and pass in the wots function prototype
		WotsTreeHash(Params, root, 0, authpath, 0, skseed, pkseed, 0, 0, toptreeaddr, stack, heights);
		// copy root and seeds to private key
		MemoryTools::Copy(root, 0, PublicKey, Params.SPX_N, Params.SPX_N);
		MemoryTools::Copy(root, 0, PrivateKey, 3 * Params.SPX_N, Params.SPX_N);
	}

	template<typename T>
	static size_t Sign(T &Params, std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<IPrng> &Rng)
	{
		// returns an array containing the signature followed by the message
		std::vector<uint32_t> heights(Params.SPX_FORS_HEIGHT + 1);
		std::vector<uint8_t> optrand(Params.SPX_N);
		std::vector<uint8_t> pk(2 * Params.SPX_N);
		std::vector<uint8_t> root(Params.SPX_N);
		std::vector<uint8_t> skseed(Params.SPX_N);
		std::vector<uint8_t> stack((Params.SPX_FORS_HEIGHT + 1) * Params.SPX_N);
		std::vector<uint8_t> mhash(Params.SPX_FORS_MSG_BYTES);
		std::vector<uint8_t> skprf(Params.SPX_N);
		std::array<uint32_t, 8> treeaddr = { 0 };
		std::array<uint32_t, 8> wotsaddr = { 0 };
		uint64_t tree;
		uint32_t idx;
		uint32_t idxsm;
		uint32_t idxleaf;

		MemoryTools::Copy(PrivateKey, 0, skseed, 0, Params.SPX_N);
		MemoryTools::Copy(PrivateKey, Params.SPX_N, skprf, 0, Params.SPX_N);
		MemoryTools::Copy(PrivateKey, 2 * Params.SPX_N, pk, 0, 2 * Params.SPX_N);
		SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
		SetType(treeaddr, SPX_ADDR_TYPE_HASHTREE);
		Signature.resize(Message.size() + Params.SPX_SIGNATURE_SIZE);

		// already put the message in the right place, to make it easier to prepend
		// things when computing the hash over the message
		// we need to do this from back to front, so that it works when sm = m
		for (idx = static_cast<uint32_t>(Message.size()); idx > 0; idx--)
		{
			Signature[Params.SPX_BYTES + idx - 1] = Message[idx - 1];
		}

		// optionally, signing can be made non-deterministic using optrand,
		// this can help counter side-channel attacks that would benefit from
		// getting a large number of traces when the signer uses the same nodes
		Rng->Generate(optrand);
		// compute the digest randomization value
		GenMessageRandom(Params, skprf, optrand, Signature, Message.size());
		// derive the message digest and leaf index from R, PK and M
		HashMessage(Params, mhash, tree, idxleaf, Signature, pk, Signature, Message.size());
		
		idxsm = Params.SPX_N;
		SetTreeAddress(wotsaddr, tree);
		SetKeypairAddress(wotsaddr, idxleaf);
		// sign the message hash using SPXPFORS
		ForsSign(Params, Signature, idxsm, root, mhash, skseed, pk, wotsaddr);
		idxsm += Params.SPX_FORS_BYTES;

		for (idx = 0; idx < Params.SPX_D; ++idx)
		{
			SetLayerAddress(treeaddr, idx);
			SetTreeAddress(treeaddr, tree);
			CopySubtreeAddress(treeaddr, wotsaddr);
			SetKeypairAddress(wotsaddr, idxleaf);
			// compute a SPXPWOTS signature
			WotsSign(Params, Signature, idxsm, root, skseed, pk, wotsaddr);
			idxsm += Params.SPX_WOTS_BYTES;

			// compute the authentication path for the used SPXPWOTS leaf
			WotsTreeHash(Params, root, 0, Signature, idxsm, skseed, pk, idxleaf, 0, treeaddr, stack, heights);

			idxsm += Params.SPX_TREE_HEIGHT * Params.SPX_N;
			// update the indices for the next layer
			idxleaf = (tree & ((1 << Params.SPX_TREE_HEIGHT) - 1));
			tree = tree >> Params.SPX_TREE_HEIGHT;
		}

		return Params.SPX_BYTES + Message.size();
	}

	template<typename T>
	static bool Verify(T &Params, std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey)
	{
		// verifies a given signature-message pair under a given public key
		const size_t MSGLEN = Signature.size() - Params.SPX_BYTES;
		std::vector<uint8_t> buf(Params.SPX_N + SPX_ADDR_BYTES + Params.SPX_WOTS_LEN * Params.SPX_N);
		std::vector<uint8_t> leaf(Params.SPX_N);
		std::vector<uint8_t> mask(Params.SPX_WOTS_LEN * Params.SPX_N);
		std::vector<uint8_t> pkroot(Params.SPX_N);
		std::vector<uint8_t> pkseed(Params.SPX_N);
		std::vector<uint8_t> root(Params.SPX_N);
		std::vector<uint8_t> tmsg(Signature.size());
		std::vector<uint8_t> wotspk(Params.SPX_WOTS_BYTES);
		uint64_t tree;
		size_t idxsig;
		uint32_t idx;
		uint32_t idxleaf;
		bool res(false);

		if (Signature.size() >= Params.SPX_BYTES)
		{
			std::vector<uint8_t> sig(Params.SPX_BYTES);
			std::vector<uint8_t> mhash(Params.SPX_FORS_MSG_BYTES);
			std::array<uint32_t, 8> treeaddr = { 0 };
			std::array<uint32_t, 8> wotsaddr = { 0 };
			std::array<uint32_t, 8> wotspkaddr = { 0 };
			// the API caller does not necessarily know what size a signature 
			// should be but SPHINCS+ signatures are always exactly T::SPX_BYTES.
			idxsig = 0;
			MemoryTools::Copy(PublicKey, Params.SPX_N, pkroot, 0, Params.SPX_N);
			MemoryTools::Copy(PublicKey, 0, pkseed, 0, Params.SPX_N);
			SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
			SetType(treeaddr, SPX_ADDR_TYPE_HASHTREE);
			SetType(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);

			// put the message all the way at the end of the message buffer, so that we can
			// prepend the required other inputs for the hash function
			MemoryTools::Copy(Signature, Params.SPX_BYTES, tmsg, Params.SPX_BYTES, MSGLEN);
			// create a copy of the signature so that m = sm is not an issue
			MemoryTools::Copy(Signature, 0, sig, 0, Params.SPX_BYTES);
			// derive the message digest and leaf index from R || PK || M
			// the additional T::SPX_N is a result of the hash domain separator
			HashMessage(Params, mhash, tree, idxleaf, sig, PublicKey, tmsg, MSGLEN);
			idxsig += Params.SPX_N;

			// layer correctly defaults to 0, so no need to set layer address
			SetTreeAddress(wotsaddr, tree);
			SetKeypairAddress(wotsaddr, idxleaf);
			ForsPkFromSig(Params, root, 0, Signature, idxsig, mhash, pkseed, wotsaddr);
			idxsig += Params.SPX_FORS_BYTES;

			// for each subtree
			for (idx = 0; idx < Params.SPX_D; ++idx)
			{
				SetLayerAddress(treeaddr, idx);
				SetTreeAddress(treeaddr, tree);
				CopySubtreeAddress(treeaddr, wotsaddr);
				SetKeypairAddress(wotsaddr, idxleaf);
				CopyKeypairAddress(wotsaddr, wotspkaddr);
				// the SPXPWOTS public key is only correct if the signature was correct
				WotsPkFromSig(Params, wotspk, sig, idxsig, root, pkseed, wotsaddr);
				idxsig += Params.SPX_WOTS_BYTES;
				// compute the leaf node using the SPXPWOTS public key
				THash(Params, leaf, 0, wotspk, 0, Params.SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask);
				// compute the root node of this subtree
				ComputeRoot(Params, root, 0, leaf, idxleaf, 0, sig, idxsig, Params.SPX_TREE_HEIGHT, pkseed, treeaddr);
				idxsig += Params.SPX_TREE_HEIGHT * Params.SPX_N;
				// update the indices for the next layer
				idxleaf = (tree & ((1 << Params.SPX_TREE_HEIGHT) - 1));
				tree = tree >> Params.SPX_TREE_HEIGHT;
			}

			res = true;
		}

		// check if the root node equals the root node in the public key
		if (!IntegerTools::Compare(root, 0, pkroot, 0, T::SPX_N))
		{
			// if failed, zero the signature
			MemoryTools::Clear(tmsg, 0, tmsg.size());
			res = false;
		}

		// if verification was successful, resize and move the message
		Message.resize(MSGLEN);
		MemoryTools::Copy(tmsg, T::SPX_BYTES, Message, 0, MSGLEN);

		return res;
	}
};

NAMESPACE_SPHINCSPLUSEND
#endif
