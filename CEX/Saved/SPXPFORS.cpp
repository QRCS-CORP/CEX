#include "SPXPFORS.h"

NAMESPACE_SPHINCSPLUS

void SPXPFORS::ComputeRoot(std::vector<uint8_t> &Root, size_t RootOffset, const std::vector<uint8_t> &Leaf, uint32_t LeafOffset, uint32_t IdxOffset, const std::vector<uint8_t> &AuthPath,
	size_t AuthOffset, uint32_t TreeHeight, const std::vector<uint8_t> &PkSeed, std::array<uint32_t, 8> &Address, size_t N)
{
	// computes a Root node given a Leaf and an auth path.
	// expects Addressess to be complete other than the tree_height and tree_index
	std::vector<uint8_t> buf1(N * 2);
	std::vector<uint8_t> buf2(N + SPX_ADDR_BYTES + (N * 2));
	std::vector<uint8_t> mask(N * 2);
	uint32_t idx;

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
		SPXPUtils::SetTreeHeight(Address, idx + 1);
		SPXPUtils::SetTreeIndex(Address, LeafOffset + IdxOffset);

		// pick the right or left neighbor, depending on parity of the node
		if (LeafOffset & 1)
		{
			SPXPUtils::THash(buf1, N, buf1, 0, 2, PkSeed, Address, buf2, mask, N);
			MemoryTools::Copy(AuthPath, AuthOffset, buf1, 0, N);
		}
		else
		{
			SPXPUtils::THash(buf1, 0, buf1, 0, 2, PkSeed, Address, buf2, mask, N);
			MemoryTools::Copy(AuthPath, AuthOffset, buf1, N, N);
		}

		AuthOffset += N;
	}

	// the last iteration is exceptional; we do not copy an AuthPath node
	LeafOffset >>= 1;
	IdxOffset >>= 1;
	SPXPUtils::SetTreeHeight(Address, TreeHeight);
	SPXPUtils::SetTreeIndex(Address, LeafOffset + IdxOffset);
	SPXPUtils::THash(Root, RootOffset, buf1, 0, 2, PkSeed, Address, buf2, mask, N);
}

void SPXPFORS::ForsGenLeaf(std::vector<uint8_t> &Leaf, size_t LeafOffset, const std::vector<uint8_t> &SecretSeed, const std::vector<uint8_t> &PublicSeed, uint32_t AddressIdx,
	const std::array<uint32_t, 8> &TreeAddress, size_t N)
{
	std::array<uint32_t, 8> leafaddress = { 0 };

	// only copy the parts that must be kept in fors_leaf_addr
	SPXPUtils::CopyKeypairAddress(TreeAddress, leafaddress);
	SPXPUtils::SetType(leafaddress, SPX_ADDR_TYPE_FORSTREE);
	SPXPUtils::SetTreeIndex(leafaddress, AddressIdx);
	ForsGenSk(Leaf, LeafOffset, SecretSeed, leafaddress, N);
	ForsSkToLeaf(Leaf, Leaf, LeafOffset, PublicSeed, leafaddress, N);
}

void SPXPFORS::ForsGenSk(std::vector<uint8_t> &Secret, size_t SecretOffset, const std::vector<uint8_t> &Seed, std::array<uint32_t, 8> &Address, size_t N)
{
	SPXPUtils::PrfAddress(Secret, SecretOffset, Seed, Address, N);
}

void SPXPFORS::ForsPkFromSig(std::vector<uint8_t> &PublicKey, size_t PubKeyOffset, const std::vector<uint8_t> &Signature, size_t SigOffset, const std::vector<uint8_t> &Message,
	const std::vector<uint8_t> &PublicSeed, const std::array<uint32_t, 8> &ForsAddress, uint32_t ForsHeight, size_t ForsTrees, size_t N)
{
	std::array<uint32_t, 8> forstreeaddr = { 0 };
	std::array<uint32_t, 8> forspkaddr = { 0 };
	std::vector<uint32_t> indices(ForsTrees * N);
	std::vector<uint8_t> leaf(N);
	std::vector<uint8_t> roots(ForsTrees * N);
	uint32_t idx;
	uint32_t idxsig;
	uint32_t idxoff;

	idxsig = static_cast<uint32_t>(SigOffset);
	SPXPUtils::CopyKeypairAddress(ForsAddress, forstreeaddr);
	SPXPUtils::CopyKeypairAddress(ForsAddress, forspkaddr);
	SPXPUtils::SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
	SPXPUtils::SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);

	MessageToIndices(indices, Message, ForsHeight, ForsTrees);

	for (idx = 0; idx < ForsTrees; ++idx)
	{
		idxoff = idx * (1 << ForsHeight);
		SPXPUtils::SetTreeHeight(forstreeaddr, 0);
		SPXPUtils::SetTreeIndex(forstreeaddr, indices[idx] + idxoff);
		// derive the leaf from the included secret key part
		ForsSkToLeaf(leaf, Signature, idxsig, PublicSeed, forstreeaddr, N);
		idxsig += static_cast<uint32_t>(N);
		// derive the corresponding root node of this tree
		ComputeRoot(roots, N * idx, leaf, indices[idx], idxoff, Signature, idxsig, ForsHeight, PublicSeed, forstreeaddr, N);
		idxsig += static_cast<uint32_t>(N) * ForsHeight;
	}

	// hash horizontally across all tree roots to derive the public key
	std::vector<uint8_t> buf(N + SPX_ADDR_BYTES + ForsTrees * N);
	std::vector<uint8_t> mask(ForsTrees * N);
	SPXPUtils::THash(PublicKey, PubKeyOffset, roots, 0, ForsTrees, PublicSeed, forspkaddr, buf, mask, N);
}

void SPXPFORS::ForsSign(std::vector<uint8_t> &Signature, size_t SigOffset, std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &Message,
	const std::vector<uint8_t> &SecretSeed, const std::vector<uint8_t> &PublicSeed, const std::array<uint32_t, 8> &ForsAddress, size_t ForsHeight, size_t ForsTrees, size_t N)
{
	std::array<uint32_t, 8> forstreeaddr = { 0 };
	std::array<uint32_t, 8> forspkaddr = { 0 };
	std::vector<uint32_t> heights(ForsHeight + 1);
	std::vector<uint32_t> indices(ForsTrees);
	std::vector<uint8_t> roots(ForsTrees * N);
	std::vector<uint8_t> stack((ForsHeight + 1) * N);
	size_t idxsm;
	size_t idx;
	size_t idxoff;

	idxsm = SigOffset;

	SPXPUtils::CopyKeypairAddress(ForsAddress, forstreeaddr);
	SPXPUtils::CopyKeypairAddress(ForsAddress, forspkaddr);
	SPXPUtils::SetType(forstreeaddr, SPX_ADDR_TYPE_FORSTREE);
	SPXPUtils::SetType(forspkaddr, SPX_ADDR_TYPE_FORSPK);
	MessageToIndices(indices, Message, ForsHeight, ForsTrees);
	
	std::function<void(std::vector<uint8_t> &,
		size_t,
		const std::vector<uint8_t> &,
		const std::vector<uint8_t> &,
		uint32_t,
		std::array<uint32_t, 8> &,
		size_t)> forsgen = ForsGenLeaf;

	for (idx = 0; idx < ForsTrees; ++idx)
	{
		idxoff = idx * (1ULL << ForsHeight);
		SPXPUtils::SetTreeHeight(forstreeaddr, 0);
		SPXPUtils::SetTreeIndex(forstreeaddr, indices[idx] + static_cast<uint32_t>(idxoff));
		// include the secret key part that produces the selected leaf node
		ForsGenSk(Signature, idxsm, SecretSeed, forstreeaddr, N);
		idxsm += N;
		// compute the authentication path for this leaf node
		SPXPUtils::TreeHash(roots, N * idx, Signature, idxsm, SecretSeed, PublicSeed, indices[idx], static_cast<uint32_t>(idxoff), static_cast<uint32_t>(ForsHeight), forstreeaddr, stack, heights, N, forsgen);
		idxsm += N * ForsHeight;
	}

	// hash horizontally across all tree roots to derive the public key
	std::vector<uint8_t> buf(N + SPX_ADDR_BYTES + (ForsTrees * N));
	std::vector<uint8_t> mask(ForsTrees * N);
	SPXPUtils::THash(PublicKey, 0, roots, 0, ForsTrees, PublicSeed, forspkaddr, buf, mask, N);
}

void SPXPFORS::ForsSkToLeaf(std::vector<uint8_t> &Leaf, const std::vector<uint8_t> &SecretKey, size_t KeyOffset, const std::vector<uint8_t> &PublicSeed, std::array<uint32_t, 8> &LeafAddress, size_t N)
{
	std::vector<uint8_t> buf(N + SPX_ADDR_BYTES + 1 * N);
	std::vector<uint8_t> mask(N);

	SPXPUtils::THash(Leaf, 0, SecretKey, KeyOffset, 1, PublicSeed, LeafAddress, buf, mask, N);
}

void SPXPFORS::GenMessageRandom(const std::vector<uint8_t> &SkPrf, const std::vector<uint8_t> &OptRnd, std::vector<uint8_t> &Message, size_t MsgOffset, size_t MsgLength, size_t N)
{
	MemoryTools::Copy(SkPrf, 0, Message, MsgOffset - (2 * N), N);
	MemoryTools::Copy(OptRnd, 0, Message, MsgOffset - N, N);

	std::vector<uint8_t> k(MsgLength + (2 * N));
	MemoryTools::Copy(Message, MsgOffset - (2 * N), k, 0, k.size());

	SPXPUtils::XOF(k, 0, k.size(), Message, 0, N, Keccak::KECCAK256_RATE_SIZE);
}

void SPXPFORS::HashMessage(std::vector<uint8_t> &Digest, uint64_t &Tree, uint32_t &LeafIndex, const std::vector<uint8_t> &Rand, const std::vector<uint8_t> &PublicKey,
	std::vector<uint8_t> &Message, size_t MsgOffset, size_t MsgLength, size_t ForsHeight, size_t ForsTrees, size_t N)
{
	const size_t FORSMSG = ((ForsHeight * ForsTrees + 7) / 8);
	const size_t TREEBITS = (SPX_TREE_HEIGHT * (SPX_D - 1));
	const size_t TREEBYTES = ((TREEBITS + 7) / 8);
	const size_t LEAFBITS = SPX_TREE_HEIGHT;
	const size_t LEAFBYTES = ((LEAFBITS + 7) / 8);
	const size_t DGSTBYTES = (FORSMSG + TREEBYTES + LEAFBYTES);
	const size_t PKBYTES = (2 * N);
	std::vector<uint8_t> buf(DGSTBYTES);

	MemoryTools::Copy(Rand, 0, Message, MsgOffset - N - PKBYTES, N);
	MemoryTools::Copy(PublicKey, 0, Message, MsgOffset - PKBYTES, PKBYTES);

	std::vector<uint8_t> k(MsgLength + N + PKBYTES);
	MemoryTools::Copy(Message, MsgOffset - N - PKBYTES, k, 0, k.size());

	SPXPUtils::XOF(k, 0, k.size(), buf, 0, DGSTBYTES, Keccak::KECCAK256_RATE_SIZE);

	MemoryTools::Copy(buf, 0, Digest, 0, FORSMSG);
	Tree = SPXPUtils::BytesToUll(buf, FORSMSG, TREEBYTES);
	Tree &= (~0ULL) >> (64 - TREEBITS);
	LeafIndex = SPXPUtils::BytesToUll(buf, FORSMSG + TREEBYTES, LEAFBYTES);
	LeafIndex &= (~0UL) >> (32 - LEAFBITS);
}

void SPXPFORS::MessageToIndices(std::vector<uint32_t> &Indices, const std::vector<uint8_t> &Messages, size_t ForsHeight, size_t ForsTrees)
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