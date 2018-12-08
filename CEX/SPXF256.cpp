#include "SPXF256.h"
#include "IntUtils.h"
#include "MemUtils.h"
#include "SphincsUtils.h"
#include "Keccak.h"

NAMESPACE_SPHINCS

using Utility::IntUtils;
using Digest::Keccak;
using Utility::MemUtils;

void SPXF256::AddressToBytes(std::vector<byte> &Output, size_t Offset, const std::array<uint, 8> &Address)
{
	size_t i;

	for (i = 0; i < 8; ++i)
	{
		SphincsUtils::UllToBytes(Output, Offset + (i * 4), Address[i], 4);
	}
}

void SPXF256::BaseW(std::vector<int> &Output, size_t OutOffset, const size_t OutLength, const std::vector<byte> &Input)
{
	// base_w algorithm as described in draft
	// interprets an array of bytes as integers in base w
	// this only works when log_w is a divisor of 8
	int32_t bits;
	int32_t inoffset;
	byte total;
	size_t i;

	bits = 0;
	inoffset = 0;
	total = 0;

	for (i = 0; i < OutLength; ++i)
	{
		if (bits == 0)
		{
			total = Input[inoffset];
			inoffset++;
			bits += 8;
		}

		bits -= SPX_WOTS_LOGW;
		Output[OutOffset] = (total >> bits) & (SPX_WOTS_W - 1);
		++OutOffset;
	}
}

void SPXF256::ChainLengths(std::vector<int> &Lengths, const std::vector<byte> &Message)
{
	// takes a message and derives the matching chain lengths
	BaseW(Lengths, 0, SPX_WOTS_LEN1, Message);
	WotsChecksum(Lengths, SPX_WOTS_LEN1, Lengths);
}

void SPXF256::ComputeRoot(std::vector<byte> &Root, size_t RootOffset, const std::vector<byte> &Leaf, uint LeafOffset, uint IdxOffset, const std::vector<byte> &AuthPath, size_t AuthOffset, uint TreeHeight, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, size_t Rate)
{
	// computes a Root node given a Leaf and an auth path.
	// expects Addressess to be complete other than the tree_height and tree_index
	std::vector<byte> buf1(2 * SPX_N);
	std::vector<byte> buf2(SPX_N + SPX_ADDR_BYTES + 2 * SPX_N);
	std::vector<byte> mask(2 * SPX_N);
	uint idx;

	// if LeafOffset is odd (last bit = 1), current path element is a right child
	// and AuthPath has to go left, otherwise it is the other way around
	if ((LeafOffset & 1) == 1)
	{
		MemUtils::Copy(Leaf, 0, buf1, SPX_N, SPX_N);
		MemUtils::Copy(AuthPath, AuthOffset, buf1, 0, SPX_N);
	}
	else
	{
		MemUtils::Copy(Leaf, 0, buf1, 0, SPX_N);
		MemUtils::Copy(AuthPath, AuthOffset, buf1, SPX_N, SPX_N);
	}

	AuthOffset += SPX_N;

	for (idx = 0; idx < TreeHeight - 1; ++idx)
	{
		LeafOffset >>= 1;
		IdxOffset >>= 1;

		// set the Addressess of the node we're creating
		SphincsUtils::SetTreeHeight(Address, idx + 1);
		SphincsUtils::SetTreeIndex(Address, LeafOffset + IdxOffset);

		// pick the right or left neighbor, depending on parity of the node
		if (LeafOffset & 1)
		{
			THash(buf1, SPX_N, buf1, 0, 2, PkSeed, Address, buf2, mask, Rate);
			MemUtils::Copy(AuthPath, AuthOffset, buf1, 0, SPX_N);
		}
		else
		{
			THash(buf1, 0, buf1, 0, 2, PkSeed, Address, buf2, mask, Rate);
			MemUtils::Copy(AuthPath, AuthOffset, buf1, SPX_N, SPX_N);
		}

		AuthOffset += SPX_N;
	}

	// the last iteration is exceptional; we do not copy an AuthPath node
	LeafOffset >>= 1;
	IdxOffset >>= 1;
	SphincsUtils::SetTreeHeight(Address, TreeHeight);
	SphincsUtils::SetTreeIndex(Address, LeafOffset + IdxOffset);
	THash(Root, RootOffset, buf1, 0, 2, PkSeed, Address, buf2, mask, Rate);
}

void SPXF256::ForsGenLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, uint AddressIdx, const std::array<uint, 8> &TreeAddress, size_t Rate)
{
	std::array<uint, 8> leafaddress = { 0 };

	// only copy the parts that must be kept in fors_leaf_addr
	SphincsUtils::CopyKeypairAddress(TreeAddress, leafaddress);
	SphincsUtils::SetType(leafaddress, SPX_ADDR_TYPE_FORSTREE);
	SphincsUtils::SetTreeIndex(leafaddress, AddressIdx);
	ForsGenSk(Leaf, 0, SecretSeed, leafaddress, Rate);
	ForsSkToLeaf(Leaf, Leaf, 0, PublicSeed, leafaddress, Rate);
}

void SPXF256::ForsGenSk(std::vector<byte> &Secret, size_t SecretOffset, const std::vector<byte> &Seed, std::array<uint, 8> &Address, size_t Rate)
{
	PrfAddress(Secret, SecretOffset, Seed, Address, Rate);
}

void SPXF256::ForsPkFromSig(std::vector<byte> &PublicKey, size_t PubKeyOffset, const std::vector<byte> &Signature, size_t SigOffset, const std::array<byte, SPX_FORS_MSG_BYTES> &Message, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, size_t Rate)
{
	std::array<uint, 8> forstreeaddr = { 0 };
	std::array<uint, 8> forspkaddr = { 0 };
	std::vector<uint> indices(SPX_FORS_TREES * SPX_N);
	std::vector<byte> leaf(SPX_N);
	std::vector<byte> roots(SPX_FORS_TREES * SPX_N);
	uint idxoffset;
	uint idxsig;
	uint idx;

	idxsig = static_cast<uint>(SigOffset);
	SphincsUtils::CopyKeypairAddress(ForsAddress, forstreeaddr);
	SphincsUtils::CopyKeypairAddress(ForsAddress, forspkaddr);
	SphincsUtils::SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
	SphincsUtils::SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);

	MessageToIndices(indices, Message);

	for (idx = 0; idx < SPX_FORS_TREES; ++idx)
	{
		idxoffset = idx * (1 << SPX_FORS_HEIGHT);
		SphincsUtils::SetTreeHeight(forstreeaddr, 0);
		SphincsUtils::SetTreeIndex(forstreeaddr, indices[idx] + idxoffset);
		// derive the leaf from the included secret key part
		ForsSkToLeaf(leaf, Signature, idxsig, PublicSeed, forstreeaddr, Rate);
		idxsig += SPX_N;
		// derive the corresponding root node of this tree
		ComputeRoot(roots, idx * SPX_N, leaf, indices[idx], idxoffset, Signature, idxsig, SPX_FORS_HEIGHT, PublicSeed, forstreeaddr, Rate);
		idxsig += SPX_N * SPX_FORS_HEIGHT;
	}

	// hash horizontally across all tree roots to derive the public key
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + SPX_FORS_TREES * SPX_N);
	std::vector<byte> mask(SPX_FORS_TREES * SPX_N);
	THash(PublicKey, 0, roots, 0, SPX_FORS_TREES, PublicSeed, forspkaddr, buf, mask, Rate);
}

void SPXF256::ForsSign(std::vector<byte> &Signature, size_t SigOffset, std::vector<byte> &PublicKey, const std::array<byte, SPX_FORS_MSG_BYTES> &Message, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, size_t Rate)
{
	std::array<uint, 8> forstreeaddr = { 0 };
	std::array<uint, 8> forspkaddr = { 0 };
	std::vector<uint> heights(SPX_FORS_HEIGHT + 1);
	std::vector<uint> indices(SPX_FORS_TREES);
	std::vector<byte> roots(SPX_FORS_TREES * SPX_N);
	std::vector<byte> stack((SPX_FORS_HEIGHT + 1) * SPX_N);
	uint idx;
	uint idxsm;
	uint idxoffset;

	idxsm = static_cast<uint>(SigOffset);

	SphincsUtils::CopyKeypairAddress(ForsAddress, forstreeaddr);
	SphincsUtils::CopyKeypairAddress(ForsAddress, forspkaddr);
	SphincsUtils::SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
	SphincsUtils::SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);
	MessageToIndices(indices, Message);

	for (idx = 0; idx < SPX_FORS_TREES; ++idx)
	{
		idxoffset = idx * (1 << SPX_FORS_HEIGHT);
		SphincsUtils::SetTreeHeight(forstreeaddr, 0);
		SphincsUtils::SetTreeIndex(forstreeaddr, indices[idx] + idxoffset);
		// include the secret key part that produces the selected leaf node
		ForsGenSk(Signature, idxsm, SecretSeed, forstreeaddr, Rate);
		idxsm += SPX_N;
		// compute the authentication path for this leaf node
		TreeHashF(roots, idx * SPX_N, Signature, idxsm, SecretSeed, PublicSeed, indices[idx], idxoffset, SPX_FORS_HEIGHT, forstreeaddr, stack, heights, Rate);
		idxsm += SPX_N * SPX_FORS_HEIGHT;
	}

	// hash horizontally across all tree roots to derive the public key
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + (SPX_FORS_TREES * SPX_N));
	std::vector<byte> mask(SPX_FORS_TREES * SPX_N);
	THash(PublicKey, 0, roots, 0, SPX_FORS_TREES, PublicSeed, forspkaddr, buf, mask, Rate);
}

void SPXF256::ForsSkToLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretKey, size_t KeyOffset, const std::vector<byte> &PublicSeed, std::array<uint, 8> &LeafAddress, size_t Rate)
{
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + 1 * SPX_N);
	std::vector<byte> mask(SPX_N);

	THash(Leaf, 0, SecretKey, KeyOffset, 1, PublicSeed, LeafAddress, buf, mask, Rate);
}

void SPXF256::GenChain(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, uint Start, uint Steps, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, size_t Rate)
{
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + 1 * SPX_N);
	std::vector<byte> mask(1 * SPX_N);
	uint idx;

	// initialize out with the value at position 'start'
	MemUtils::Copy(Input, InOffset, Output, OutOffset, SPX_N);

	// iterate 'steps' calls to the hash function
	for (idx = Start; idx < (Start + Steps) && idx < SPX_WOTS_W; ++idx)
	{
		SphincsUtils::SetHashAddress(Address, idx);
		THash(Output, OutOffset, Output, OutOffset, 1, PkSeed, Address, buf, mask, Rate);
	}
}

void SPXF256::GenMessageRandom(const std::array<byte, SPX_N> &SkPrf, const std::vector<byte> &OptRnd, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, size_t Rate)
{
	MemUtils::Copy(SkPrf, 0, Message, MsgOffset - (2 * SPX_N), SPX_N);
	MemUtils::Copy(OptRnd, 0, Message, MsgOffset - SPX_N, SPX_N);

	std::vector<byte> k(MsgLength + (2 * SPX_N));
	MemUtils::Copy(Message, MsgOffset - (2 * SPX_N), k, 0, k.size());

	XOF(k, 0, k.size(), Message, 0, SPX_N, Rate);
}

void SPXF256::HashMessage(std::array<byte, SPX_FORS_MSG_BYTES> &Digest, ulong &Tree, uint &LeafIndex, const std::vector<byte> &Rand, const std::vector<byte> &PublicKey, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, size_t Rate)
{
	const int32_t SPX_TREE_BITS = (SPX_TREE_HEIGHT * (SPX_D - 1));
	const int32_t SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8);
	const int32_t SPX_LEAF_BITS = SPX_TREE_HEIGHT;
	const int32_t SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8);
	const int32_t SPX_DGST_BYTES = (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES);
	std::vector<byte> buf(SPX_DGST_BYTES);

	MemUtils::Copy(Rand, 0, Message, MsgOffset - SPX_N - SPX_PK_BYTES, SPX_N);
	MemUtils::Copy(PublicKey, 0, Message, MsgOffset - SPX_PK_BYTES, SPX_PK_BYTES);

	std::vector<byte> k(MsgLength + SPX_N + SPX_PK_BYTES);
	MemUtils::Copy(Message, MsgOffset - SPX_N - SPX_PK_BYTES, k, 0, k.size());

	XOF(k, 0, k.size(), buf, 0, SPX_DGST_BYTES, Rate);

	MemUtils::Copy(buf, 0, Digest, 0, SPX_FORS_MSG_BYTES);
	Tree = SphincsUtils::BytesToUll(buf, SPX_FORS_MSG_BYTES, SPX_TREE_BYTES);
	Tree &= (~(ulong)0) >> (64 - SPX_TREE_BITS);
	LeafIndex = SphincsUtils::BytesToUll(buf, SPX_FORS_MSG_BYTES + SPX_TREE_BYTES, SPX_LEAF_BYTES);
	LeafIndex &= (~(uint)0) >> (32 - SPX_LEAF_BITS);
}

void SPXF256::MessageToIndices(std::vector<uint> &Indices, const std::array<byte, SPX_FORS_MSG_BYTES> &Messages)
{
	size_t i;
	size_t j;
	size_t offset;

	offset = 0;

	for (i = 0; i < SPX_FORS_TREES; i++)
	{
		Indices[i] = 0;
		for (j = 0; j < SPX_FORS_HEIGHT; j++)
		{
			Indices[i] <<= 1;
			Indices[i] ^= (Messages[offset >> 3] >> (offset & 0x7)) & 0x1;
			++offset;
		}
	}
}

void SPXF256::PrfAddress(std::vector<byte> &Output, size_t Offset, const std::vector<byte> &Key, const std::array<uint, 8> &Address, size_t Rate)
{
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES);

	MemUtils::Copy(Key, 0, buf, 0, SPX_N);
	AddressToBytes(buf, SPX_N, Address);

	std::vector<byte> k(SPX_N + SPX_ADDR_BYTES);
	MemUtils::Copy(buf, 0, k, 0, k.size());

	XOF(k, 0, k.size(), Output, Offset, SPX_N, Rate);
}

void SPXF256::THash(std::vector<byte> &Output, size_t OutOffset, const std::vector<byte> &Input, size_t InOffset, const uint InputBlocks, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, std::vector<byte> &Buffer, std::vector<byte> &Mask, size_t Rate)
{
	size_t i;

	MemUtils::Clear(Buffer, 0, Buffer.size());
	MemUtils::Clear(Mask, 0, Mask.size());
	MemUtils::Copy(PkSeed, 0, Buffer, 0, SPX_N);
	AddressToBytes(Buffer, SPX_N, Address);

	std::vector<byte> k(SPX_N + SPX_ADDR_BYTES);
	MemUtils::Copy(Buffer, 0, k, 0, k.size());

	XOF(k, 0, k.size(), Mask, 0, InputBlocks * SPX_N, Rate);

	for (i = 0; i < InputBlocks * SPX_N; ++i)
	{
		Buffer[SPX_N + SPX_ADDR_BYTES + i] = Input[InOffset + i] ^ Mask[i];
	}

	k.resize(SPX_N + SPX_ADDR_BYTES + InputBlocks * SPX_N);
	MemUtils::Copy(Buffer, 0, k, 0, k.size());

	XOF(k, 0, k.size(), Output, OutOffset, SPX_N, Rate);
}

void SPXF256::TreeHashF(std::vector<byte> &Root, size_t RootOffset, std::vector<byte> &Authpath, size_t AuthOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint LeafIndex,
	uint IndexOffset, uint TreeHeight, std::array<uint, 8> &TreeAddress, std::vector<byte> &Stack, std::vector<uint> &Heights, size_t Rate)
{
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + 2 * SPX_N);
	std::vector<byte> leaf(SPX_N);
	std::vector<byte> mask(2 * SPX_N);
	uint idx;
	uint treeidx;
	size_t offset;

	offset = 0;
	// idx=1024, th=10
	for (idx = 0; idx < static_cast<uint>(1 << TreeHeight); ++idx)
	{
		// add the next leaf node to the stack
		ForsGenLeaf(leaf, SkSeed, PkSeed, idx + IndexOffset, TreeAddress, Rate);
		MemUtils::Copy(leaf, 0, Stack, offset * SPX_N, SPX_N);
		offset++;
		Heights[offset - 1] = 0;

		// if this is a node we need for the auth path
		if ((LeafIndex ^ 0x1) == idx)
		{
			MemUtils::Copy(Stack, ((offset - 1) * SPX_N), Authpath, AuthOffset, SPX_N);
		}

		// while the top-most nodes are of equal height
		while (offset >= 2 && Heights[offset - 1] == Heights[offset - 2])
		{
			// compute index of the new node, in the next layer
			treeidx = (idx >> (Heights[offset - 1] + 1));
			// set the address of the node we're creating
			SphincsUtils::SetTreeHeight(TreeAddress, Heights[offset - 1] + 1);
			SphincsUtils::SetTreeIndex(TreeAddress, treeidx + (IndexOffset >> (Heights[offset - 1] + 1)));
			// hash the top-most nodes from the stack together
			THash(Stack, ((offset - 2) * SPX_N), Stack, ((offset - 2) * SPX_N), 2, PkSeed, TreeAddress, buf, mask, Rate);
			--offset;
			// note that the top-most node is now one layer higher
			++Heights[offset - 1];

			// if this is a node we need for the auth path
			if (((LeafIndex >> Heights[offset - 1]) ^ 0x1) == treeidx)
			{
				MemUtils::Copy(Stack, (offset - 1) * SPX_N, Authpath, AuthOffset + (Heights[offset - 1] * SPX_N), SPX_N);
			}
		}
	}

	MemUtils::Copy(Stack, 0, Root, RootOffset, SPX_N);
}

void SPXF256::TreeHashW(std::vector<byte> &Root, std::vector<byte> &Authpath, size_t AuthOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint LeafIndex,
	uint IndexOffset, uint TreeHeight, std::array<uint, 8> &TreeAddress, std::vector<byte> &Stack, std::vector<uint> &Heights, size_t Rate)
{
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + 2 * SPX_N);
	std::vector<byte> mask(2 * SPX_N);
	size_t offset;
	uint idx;
	uint treeidx;

	offset = 0;

	for (idx = 0; idx < (uint)(1 << TreeHeight); idx++)
	{
		// add the next leaf node to the stack
		WotsGenLeaf(Stack, offset * static_cast<size_t>(SPX_N), SkSeed, PkSeed, idx + IndexOffset, TreeAddress, Rate);
		offset++;
		Heights[offset - 1] = 0;

		// if this is a node we need for the auth path
		if ((LeafIndex ^ 0x1) == idx)
		{
			MemUtils::Copy(Stack, ((offset - 1) * SPX_N), Authpath, AuthOffset, SPX_N);
		}

		// while the top-most nodes are of equal height
		while (offset >= 2 && Heights[offset - 1] == Heights[offset - 2])
		{
			// compute index of the new node, in the next layer
			treeidx = (idx >> (Heights[offset - 1] + 1));
			// set the address of the node we're creating
			SphincsUtils::SetTreeHeight(TreeAddress, Heights[offset - 1] + 1);
			SphincsUtils::SetTreeIndex(TreeAddress, treeidx + (IndexOffset >> (Heights[offset - 1] + 1)));
			// hash the top-most nodes from the stack together
			THash(Stack, ((offset - 2) * SPX_N), Stack, ((offset - 2) * SPX_N), 2, PkSeed, TreeAddress, buf, mask, Rate);
			offset--;
			// note that the top-most node is now one layer higher
			Heights[offset - 1]++;

			// if this is a node we need for the auth path
			if (((LeafIndex >> Heights[offset - 1]) ^ 0x1) == treeidx)
			{
				MemUtils::Copy(Stack, ((offset - 1) * SPX_N), Authpath, AuthOffset + Heights[offset - 1] * SPX_N, SPX_N);
			}
		}
	}

	MemUtils::Copy(Stack, 0, Root, 0, SPX_N);
}

void SPXF256::WotsChecksum(std::vector<int> &CSumBaseW, size_t BaseOffset, const std::vector<int> &MsgBaseW)
{
	// computes the WOTS+ checksum over a message (in base_w)
	std::vector<byte> csumbytes((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8);
	ulong csum;
	uint idx;

	csum = 0;

	// compute checksum
	for (idx = 0; idx < SPX_WOTS_LEN1; ++idx)
	{
		csum += (SPX_WOTS_W - 1) - MsgBaseW[idx];
	}

	// convert checksum to base_w
	// make sure expected empty zero bits are the least significant bits
	csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
	SphincsUtils::UllToBytes(csumbytes, 0, csum, csumbytes.size());
	BaseW(CSumBaseW, BaseOffset, SPX_WOTS_LEN2, csumbytes);
}

void SPXF256::WotsGenLeaf(std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, uint AddressIndex, const std::array<uint, 8> &TreeAddress, size_t Rate)
{
	// computes the leaf at a given address. First generates the WOTS key pair, then computes leaf by hashing horizontally
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N);
	std::vector<byte> mask(SPX_WOTS_LEN * SPX_N);
	std::vector<byte> pk(SPX_WOTS_BYTES);
	std::array<uint, 8> wotsaddr = { 0 };
	std::array<uint, 8> wotspkaddr = { 0 };

	SphincsUtils::SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
	SphincsUtils::SetType(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);
	SphincsUtils::CopySubtreeAddress(TreeAddress, wotsaddr);
	SphincsUtils::SetKeypairAddress(wotsaddr, AddressIndex);

	WotsGenPk(pk, SkSeed, PkSeed, wotsaddr, Rate);
	SphincsUtils::CopyKeypairAddress(wotsaddr, wotspkaddr);
	THash(Leaf, LeafOffset, pk, 0, SPX_WOTS_LEN, PkSeed, wotspkaddr, buf, mask, Rate);
}

void SPXF256::WotsGenPk(std::vector<byte> &PublicKey, const std::vector<byte> &SkSeed, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, size_t Rate)
{
	uint idx;

	for (idx = 0; idx < SPX_WOTS_LEN; ++idx)
	{
		SphincsUtils::SetChainAddress(Address, idx);
		WotsGenSk(PublicKey, idx * SPX_N, SkSeed, Address, Rate);
		GenChain(PublicKey, idx * SPX_N, PublicKey, idx * SPX_N, 0, SPX_WOTS_W - 1, PkSeed, Address, Rate);
	}
}

void SPXF256::WotsGenSk(std::vector<byte> &Key, size_t Offset, const std::vector<byte> &KeySeed, std::array<uint, 8> &WotsAddress, size_t Rate)
{
	// make sure that the hash address is actually zeroed
	SphincsUtils::SetHashAddress(WotsAddress, 0);
	// generate sk element
	PrfAddress(Key, Offset, KeySeed, WotsAddress, Rate);
}

void SPXF256::WotsPkFromSig(std::vector<byte> &PublicKey, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &PrivateSeed, std::array<uint, 8> &Address, size_t Rate)
{
	std::vector<int> lengths(SPX_WOTS_LEN);
	uint idx;

	ChainLengths(lengths, Message);

	for (idx = 0; idx < SPX_WOTS_LEN; ++idx)
	{
		SphincsUtils::SetChainAddress(Address, idx);
		GenChain(PublicKey, idx * SPX_N, Signature, SigOffset + (idx * SPX_N), lengths[idx], (SPX_WOTS_W - 1) - lengths[idx], PrivateSeed, Address, Rate);
	}
}

void SPXF256::WotsSign(std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, std::array<uint, 8> &Address, size_t Rate)
{
	std::vector<int> lengths(SPX_WOTS_LEN);
	uint idx;

	ChainLengths(lengths, Message);

	for (idx = 0; idx < SPX_WOTS_LEN; ++idx)
	{
		SphincsUtils::SetChainAddress(Address, idx);
		WotsGenSk(Signature, SigOffset + (idx * SPX_N), SecretSeed, Address, Rate);
		GenChain(Signature, SigOffset + (idx * SPX_N), Signature, SigOffset + (idx * SPX_N), 0, lengths[idx], PublicSeed, Address, Rate);
	}
}

void SPXF256::XOF(const std::vector<byte> &Input, size_t InOffset, size_t InLength, std::vector<byte> &Output, size_t OutOffset, size_t OutLength, size_t Rate)
{
#if defined(CEX_SHAKE_STRONG)
	Keccak::XOFR48P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#else
	Keccak::XOFR24P1600(Input, InOffset, InLength, Output, OutOffset, OutLength, Rate);
#endif
}

void SPXF256::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, SphincsParameters Parameters)
{
	// we do not need the auth path in key generation, but it simplifies the
	// code to have just one treehash routine that computes both root and path in one function

	std::array<uint, 8> toptreeaddr = { 0 };
	std::vector<uint> heights(SPX_TREE_HEIGHT + 1);
	std::vector<byte> stack((SPX_TREE_HEIGHT + 1) * SPX_N);
	std::vector<byte> authpath(SPX_TREE_HEIGHT * SPX_N);
	std::vector<byte> root(SPX_N);
	std::vector<byte> pkseed(SPX_N);
	std::vector<byte> skseed(SPX_N);
	size_t rate;

	rate = (Parameters == SphincsParameters::SPXS128F256) ? 168 : (Parameters == SphincsParameters::SPXS256F256) ? 136 : 72;
	SphincsUtils::SetLayerAddress(toptreeaddr, SPX_D - 1);
	SphincsUtils::SetType(toptreeaddr, SPX_ADDR_TYPE_HASHTREE);

	// initialize skprf, skseed, and pkseed
	Rng->Generate(PrivateKey, SPX_N, SPX_N);
	Rng->Generate(pkseed, 0, SPX_N);
	Rng->Generate(skseed, 0, SPX_N);

	// compute root node of the top-most subtree
	TreeHashW(root, authpath, 0, skseed, pkseed, 0, 0, SPX_TREE_HEIGHT, toptreeaddr, stack, heights, rate);

	// copy root and seeds to private key
	MemUtils::Copy(root, 0, PrivateKey, 3 * SPX_N, SPX_N);
	MemUtils::Copy(pkseed, 0, PrivateKey, 2 * SPX_N, SPX_N);
	MemUtils::Copy(skseed, 0, PrivateKey, 0, SPX_N);
	// copy root and pkseed to public key
	MemUtils::Copy(PrivateKey, 2 * SPX_N, PublicKey, 0, 2 * SPX_N);
}

size_t SPXF256::Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng, SphincsParameters Parameters)
{
	// returns an array containing the signature followed by the message

	std::vector<byte> pk(2 * SPX_N);
	std::array<byte, SPX_N> skprf;
	std::vector<byte> skseed(SPX_N);
	std::vector<uint> heights(SPX_FORS_HEIGHT + 1);
	std::array<byte, SPX_FORS_MSG_BYTES> mhash;
	std::vector<byte> optrand(SPX_N);
	std::vector<byte> root(SPX_N);
	std::vector<byte> stack((SPX_FORS_HEIGHT + 1) * SPX_N);
	std::array<uint, 8> treeaddr = { 0 };
	std::array<uint, 8> wotsaddr = { 0 };
	ulong tree;
	uint idx;
	uint idxleaf;
	uint idxsm;
	size_t rate;

	rate = (Parameters == SphincsParameters::SPXS128F256) ? 168 : (Parameters == SphincsParameters::SPXS256F256) ? 136 : 72;
	MemUtils::Copy(PrivateKey, 0, skseed, 0, SPX_N);
	MemUtils::Copy(PrivateKey, SPX_N, skprf, 0, SPX_N);
	MemUtils::Copy(PrivateKey, 2 * SPX_N, pk, 0, 2 * SPX_N);
	SphincsUtils::SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
	SphincsUtils::SetType(treeaddr, SPX_ADDR_TYPE_HASHTREE);
	Signature.resize(Message.size() + SPHINCS_SIGNATURE_SIZE);

	// already put the message in the right place, to make it easier to prepend
	// things when computing the hash over the message
	// we need to do this from back to front, so that it works when sm = m
	for (idx = static_cast<uint>(Message.size()); idx > 0; idx--)
	{
		Signature[SPX_BYTES + idx - 1] = Message[idx - 1];
	}

	// optionally, signing can be made non-deterministic using optrand,
	// this can help counter side-channel attacks that would benefit from
	// getting a large number of traces when the signer uses the same nodes
	Rng->Generate(optrand);
	// compute the digest randomization value
	GenMessageRandom(skprf, optrand, Signature, SPX_BYTES, Message.size(), rate);
	// derive the message digest and leaf index from R, PK and M
	HashMessage(mhash, tree, idxleaf, Signature, pk, Signature, SPX_BYTES, Message.size(), rate);

	idxsm = SPX_N;
	SphincsUtils::SetTreeAddress(wotsaddr, tree);
	SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
	// sign the message hash using FORS
	ForsSign(Signature, idxsm, root, mhash, skseed, pk, wotsaddr, rate);
	//fors_sign(Signature.data() + idxsm, root.data(), mhash.data(), skseed.data(), pk.data(), wotsaddr.data()); //.38
	idxsm += SPX_FORS_BYTES;

	for (idx = 0; idx < SPX_D; ++idx)
	{
		SphincsUtils::SetLayerAddress(treeaddr, idx);
		SphincsUtils::SetTreeAddress(treeaddr, tree);
		SphincsUtils::CopySubtreeAddress(treeaddr, wotsaddr);
		SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
		// compute a WOTS signature
		WotsSign(Signature, idxsm, root, skseed, pk, wotsaddr, rate);
		idxsm += SPX_WOTS_BYTES;
		// compute the authentication path for the used WOTS leaf
		TreeHashW(root, Signature, idxsm, skseed, pk, idxleaf, 0, SPX_TREE_HEIGHT, treeaddr, stack, heights, rate);
		//treehash(root.data(), Signature.data() + idxsm, skseed.data(), pk.data(), idxleaf, 0, SPX_TREE_HEIGHT, treeaddr.data(), stack.data(), heights.data(), wots_gen_leaf);
		idxsm += SPX_TREE_HEIGHT * SPX_N;
		// update the indices for the next layer
		idxleaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
		tree = tree >> SPX_TREE_HEIGHT;
	}

	return SPX_BYTES + Message.size();
}

uint SPXF256::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, SphincsParameters Parameters)
{
	// verifies a given signature-message pair under a given public key

	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N);
	std::vector<byte> leaf(SPX_N);
	std::vector<byte> mask(SPX_WOTS_LEN * SPX_N);
	std::array<byte, SPX_FORS_MSG_BYTES> mhash;
	std::vector<byte> pkroot(SPX_N);
	std::vector<byte> pkseed(SPX_N);
	std::vector<byte> root(SPX_N);
	std::vector<byte> sig(SPX_BYTES);
	std::vector<byte> tmsg(Signature.size());
	std::vector<byte> wotspk(SPX_WOTS_BYTES);
	std::array<uint, 8> treeaddr = { 0 };
	std::array<uint, 8> wotsaddr = { 0 };
	std::array<uint, 8> wotspkaddr = { 0 };
	ulong tree;
	size_t idxsig;
	size_t msglen;
	uint idx;
	uint idxleaf;
	size_t rate;

	rate = (Parameters == SphincsParameters::SPXS128F256) ? 168 : (Parameters == SphincsParameters::SPXS256F256) ? 136 : 72;
	idxsig = 0;
	MemUtils::Copy(PublicKey, SPX_N, pkroot, 0, SPX_N);
	MemUtils::Copy(PublicKey, 0, pkseed, 0, SPX_N);
	SphincsUtils::SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
	SphincsUtils::SetType(treeaddr, SPX_ADDR_TYPE_HASHTREE);
	SphincsUtils::SetType(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);
	msglen = Signature.size() - SPX_BYTES;

	// the API caller does not necessarily know what size a signature 
	// should be but SPHINCS+ signatures are always exactly SPX_BYTES
	if (Signature.size() < SPX_BYTES)
	{
		return 0;
	}

	// put the message all the way at the end of the m buffer, so that we can
	// prepend the required other inputs for the hash function
	MemUtils::Copy(Signature, SPX_BYTES, tmsg, SPX_BYTES, msglen);
	// create a copy of the signature so that m = sm is not an issue
	MemUtils::Copy(Signature, 0, sig, 0, SPX_BYTES);
	// derive the message digest and leaf index from R || PK || M
	// the additional SPX_N is a result of the hash domain separator
	HashMessage(mhash, tree, idxleaf, sig, PublicKey, tmsg, SPX_BYTES, msglen, rate);
	idxsig += SPX_N;

	// layer correctly defaults to 0, so no need to set layer address
	SphincsUtils::SetTreeAddress(wotsaddr, tree);
	SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
	ForsPkFromSig(root, 0, Signature, idxsig, mhash, pkseed, wotsaddr, rate);
	idxsig += SPX_FORS_BYTES;

	// for each subtree
	for (idx = 0; idx < SPX_D; ++idx)
	{
		SphincsUtils::SetLayerAddress(treeaddr, idx);
		SphincsUtils::SetTreeAddress(treeaddr, tree);
		SphincsUtils::CopySubtreeAddress(treeaddr, wotsaddr);
		SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
		SphincsUtils::CopyKeypairAddress(wotsaddr, wotspkaddr);
		// the WOTS public key is only correct if the signature was correct
		WotsPkFromSig(wotspk, sig, idxsig, root, pkseed, wotsaddr, rate);
		idxsig += SPX_WOTS_BYTES;
		// compute the leaf node using the WOTS public key
		THash(leaf, 0, wotspk, 0, SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask, rate);
		// compute the root node of this subtree
		ComputeRoot(root, 0, leaf, idxleaf, 0, sig, idxsig, SPX_TREE_HEIGHT, pkseed, treeaddr, rate);
		idxsig += SPX_TREE_HEIGHT * SPX_N;
		// update the indices for the next layer
		idxleaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
		tree = tree >> SPX_TREE_HEIGHT;
	}

	// check if the root node equals the root node in the public key
	if (!IntUtils::Compare(root, 0, pkroot, 0, SPX_N))
	{
		// if not, zero the message
		MemUtils::Clear(tmsg, 0, tmsg.size());

		return 0;
	}

	// if verification was successful, resize and move the message
	Message.resize(msglen);
	MemUtils::Copy(tmsg, SPX_BYTES, Message, 0, msglen);

	return 1;
}

NAMESPACE_SPHINCSEND