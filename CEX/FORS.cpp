#include "FORS.h"

NAMESPACE_SPHINCS

void FORS::ComputeRoot(std::vector<byte> &Root, size_t RootOffset, const std::vector<byte> &Leaf, uint LeafOffset, uint IdxOffset, const std::vector<byte> &AuthPath,
	size_t AuthOffset, uint TreeHeight, const std::vector<byte> &PkSeed, std::array<uint, 8> &Address, size_t N)
{
	// computes a Root node given a Leaf and an auth path.
	// expects Addressess to be complete other than the tree_height and tree_index
	std::vector<byte> buf1(N * 2);
	std::vector<byte> buf2(N + SPX_ADDR_BYTES + (N * 2));
	std::vector<byte> mask(N * 2);
	uint idx;

	// if LeafOffset is odd (last bit = 1), current path element is a right child
	// and AuthPath has to go left, otherwise it is the other way around
	if ((LeafOffset & 1) == 1)
	{
		MemoryTools::Copy(Leaf, 0, buf1, N, N);
		MemoryTools::Copy(AuthPath, AuthOffset, buf1, 0, N);
	}
	else
	{
		MemoryTools::Copy(Leaf, 0, buf1, 0, N);
		MemoryTools::Copy(AuthPath, AuthOffset, buf1, N, N);
	}

	AuthOffset += N;

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
			SphincsUtils::THash(buf1, N, buf1, 0, 2, PkSeed, Address, buf2, mask, N);
			MemoryTools::Copy(AuthPath, AuthOffset, buf1, 0, N);
		}
		else
		{
			SphincsUtils::THash(buf1, 0, buf1, 0, 2, PkSeed, Address, buf2, mask, N);
			MemoryTools::Copy(AuthPath, AuthOffset, buf1, N, N);
		}

		AuthOffset += N;
	}

	// the last iteration is exceptional; we do not copy an AuthPath node
	LeafOffset >>= 1;
	IdxOffset >>= 1;
	SphincsUtils::SetTreeHeight(Address, TreeHeight);
	SphincsUtils::SetTreeIndex(Address, LeafOffset + IdxOffset);
	SphincsUtils::THash(Root, RootOffset, buf1, 0, 2, PkSeed, Address, buf2, mask, N);
}

void FORS::ForsGenLeaf(std::vector<byte> &Leaf, size_t LeafOffset, const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, uint AddressIdx,
	const std::array<uint, 8> &TreeAddress, size_t N)
{
	std::array<uint, 8> leafaddress = { 0 };

	// only copy the parts that must be kept in fors_leaf_addr
	SphincsUtils::CopyKeypairAddress(TreeAddress, leafaddress);
	SphincsUtils::SetType(leafaddress, SPX_ADDR_TYPE_FORSTREE);
	SphincsUtils::SetTreeIndex(leafaddress, AddressIdx);
	ForsGenSk(Leaf, LeafOffset, SecretSeed, leafaddress, N);
	ForsSkToLeaf(Leaf, Leaf, LeafOffset, PublicSeed, leafaddress, N);
}

void FORS::ForsGenSk(std::vector<byte> &Secret, size_t SecretOffset, const std::vector<byte> &Seed, std::array<uint, 8> &Address, size_t N)
{
	SphincsUtils::PrfAddress(Secret, SecretOffset, Seed, Address, N);
}

void FORS::ForsPkFromSig(std::vector<byte> &PublicKey, size_t PubKeyOffset, const std::vector<byte> &Signature, size_t SigOffset, const std::vector<byte> &Message,
	const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, uint ForsHeight, size_t ForsTrees, size_t N)
{
	std::array<uint, 8> forstreeaddr = { 0 };
	std::array<uint, 8> forspkaddr = { 0 };
	std::vector<uint> indices(ForsTrees * N);
	std::vector<byte> leaf(N);
	std::vector<byte> roots(ForsTrees * N);
	uint idx;
	uint idxsig;
	uint idxoff;

	idxsig = static_cast<uint>(SigOffset);
	SphincsUtils::CopyKeypairAddress(ForsAddress, forstreeaddr);
	SphincsUtils::CopyKeypairAddress(ForsAddress, forspkaddr);
	SphincsUtils::SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
	SphincsUtils::SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);

	MessageToIndices(indices, Message, ForsHeight, ForsTrees);

	for (idx = 0; idx < ForsTrees; ++idx)
	{
		idxoff = idx * (1 << ForsHeight);
		SphincsUtils::SetTreeHeight(forstreeaddr, 0);
		SphincsUtils::SetTreeIndex(forstreeaddr, indices[idx] + idxoff);
		// derive the leaf from the included secret key part
		ForsSkToLeaf(leaf, Signature, idxsig, PublicSeed, forstreeaddr, N);
		idxsig += static_cast<uint>(N);
		// derive the corresponding root node of this tree
		ComputeRoot(roots, idx * static_cast<uint>(N), leaf, indices[idx], idxoff, Signature, idxsig, ForsHeight, PublicSeed, forstreeaddr, N);
		idxsig += static_cast<uint>(N) * ForsHeight;
	}

	// hash horizontally across all tree roots to derive the public key
	std::vector<byte> buf(N + SPX_ADDR_BYTES + ForsTrees * N);
	std::vector<byte> mask(ForsTrees * N);
	SphincsUtils::THash(PublicKey, 0, roots, 0, ForsTrees, PublicSeed, forspkaddr, buf, mask, N);
}

void FORS::ForsSign(std::vector<byte> &Signature, size_t SigOffset, std::vector<byte> &PublicKey, const std::vector<byte> &Message,
	const std::vector<byte> &SecretSeed, const std::vector<byte> &PublicSeed, const std::array<uint, 8> &ForsAddress, size_t ForsHeight, size_t ForsTrees, size_t N)
{
	std::array<uint, 8> forstreeaddr = { 0 };
	std::array<uint, 8> forspkaddr = { 0 };
	std::vector<uint> heights(ForsHeight + 1);
	std::vector<uint> indices(ForsTrees);
	std::vector<byte> roots(ForsTrees * N);
	std::vector<byte> stack((ForsHeight + 1) * N);
	uint idx;
	uint idxsm;
	uint idxoff;

	idxsm = static_cast<uint>(SigOffset);

	SphincsUtils::CopyKeypairAddress(ForsAddress, forstreeaddr);
	SphincsUtils::CopyKeypairAddress(ForsAddress, forspkaddr);
	SphincsUtils::SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
	SphincsUtils::SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);
	MessageToIndices(indices, Message, ForsHeight, ForsTrees);

	std::function<void(std::vector<byte> &,
		size_t,
		const std::vector<byte> &,
		const std::vector<byte> &,
		uint,
		std::array<uint, 8> &,
		size_t)> forsgen = ForsGenLeaf;

	for (idx = 0; idx < ForsTrees; ++idx)
	{
		idxoff = idx * (1 << ForsHeight);
		SphincsUtils::SetTreeHeight(forstreeaddr, 0);
		SphincsUtils::SetTreeIndex(forstreeaddr, indices[idx] + idxoff);
		// include the secret key part that produces the selected leaf node
		ForsGenSk(Signature, idxsm, SecretSeed, forstreeaddr, N);
		idxsm += static_cast<uint>(N);
		// compute the authentication path for this leaf node
		SphincsUtils::TreeHash(roots, idx * N, Signature, idxsm, SecretSeed, PublicSeed, indices[idx], idxoff, ForsHeight, forstreeaddr, stack, heights, N, forsgen);
		idxsm += static_cast<uint>(N) * ForsHeight;
	}

	// hash horizontally across all tree roots to derive the public key
	std::vector<byte> buf(N + SPX_ADDR_BYTES + (ForsTrees * N));
	std::vector<byte> mask(ForsTrees * N);
	SphincsUtils::THash(PublicKey, 0, roots, 0, ForsTrees, PublicSeed, forspkaddr, buf, mask, N);
}

void FORS::ForsSkToLeaf(std::vector<byte> &Leaf, const std::vector<byte> &SecretKey, size_t KeyOffset, const std::vector<byte> &PublicSeed, std::array<uint, 8> &LeafAddress, size_t N)
{
	std::vector<byte> buf(N + SPX_ADDR_BYTES + 1 * N);
	std::vector<byte> mask(N);

	SphincsUtils::THash(Leaf, 0, SecretKey, KeyOffset, 1, PublicSeed, LeafAddress, buf, mask, N);
}

void FORS::GenMessageRandom(const std::vector<byte> &SkPrf, const std::vector<byte> &OptRnd, std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, size_t N)
{
	MemoryTools::Copy(SkPrf, 0, Message, MsgOffset - (2 * N), N);
	MemoryTools::Copy(OptRnd, 0, Message, MsgOffset - N, N);

	std::vector<byte> k(MsgLength + (2 * N));
	MemoryTools::Copy(Message, MsgOffset - (2 * N), k, 0, k.size());

	SphincsUtils::XOF(k, 0, k.size(), Message, 0, N, Keccak::KECCAK256_RATE_SIZE);
}

void FORS::HashMessage(std::vector<byte> &Digest, ulong &Tree, uint &LeafIndex, const std::vector<byte> &Rand, const std::vector<byte> &PublicKey,
	std::vector<byte> &Message, size_t MsgOffset, size_t MsgLength, size_t ForsHeight, size_t ForsTrees, size_t N)
{
	const size_t SPX_FORS_MSG_BYTES = ((ForsHeight * ForsTrees + 7) / 8);
	const size_t SPX_TREE_BITS = (SPX_TREE_HEIGHT * (SPX_D - 1));
	const size_t SPX_TREE_BYTES = ((SPX_TREE_BITS + 7) / 8);
	const size_t SPX_LEAF_BITS = SPX_TREE_HEIGHT;
	const size_t SPX_LEAF_BYTES = ((SPX_LEAF_BITS + 7) / 8);
	const size_t SPX_DGST_BYTES = (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES);
	const size_t SPX_PK_BYTES = (2 * N);
	std::vector<byte> buf(SPX_DGST_BYTES);

	MemoryTools::Copy(Rand, 0, Message, MsgOffset - N - SPX_PK_BYTES, N);
	MemoryTools::Copy(PublicKey, 0, Message, MsgOffset - SPX_PK_BYTES, SPX_PK_BYTES);

	std::vector<byte> k(MsgLength + N + SPX_PK_BYTES);
	MemoryTools::Copy(Message, MsgOffset - N - SPX_PK_BYTES, k, 0, k.size());

	SphincsUtils::XOF(k, 0, k.size(), buf, 0, SPX_DGST_BYTES, Keccak::KECCAK256_RATE_SIZE);

	MemoryTools::Copy(buf, 0, Digest, 0, SPX_FORS_MSG_BYTES);
	Tree = SphincsUtils::BytesToUll(buf, SPX_FORS_MSG_BYTES, SPX_TREE_BYTES);
	Tree &= (~0ULL) >> (64 - SPX_TREE_BITS);
	LeafIndex = SphincsUtils::BytesToUll(buf, SPX_FORS_MSG_BYTES + SPX_TREE_BYTES, SPX_LEAF_BYTES);
	LeafIndex &= (~0UL) >> (32 - SPX_LEAF_BITS);
}

void FORS::MessageToIndices(std::vector<uint> &Indices, const std::vector<byte> &Messages, size_t ForsHeight, size_t ForsTrees)
{
	// Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
	// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	// Assumes indices has space for SPX_FORS_TREES integers. 

	size_t i;
	size_t j;
	size_t oft;

	oft = 0;

	for (i = 0; i < ForsTrees; ++i)
	{
		Indices[i] = 0;

		for (j = 0; j < ForsHeight; ++j)
		{
			Indices[i] ^= ((Messages[oft >> 3] >> (oft & 0x07)) & 0x01) << j;
			++oft;
		}
	}
}

NAMESPACE_SPHINCSEND