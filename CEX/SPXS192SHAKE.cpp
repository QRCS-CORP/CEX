#include "SPXS192SHAKE.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "SphincsUtils.h"
#include "FORS.h"
#include "WOTS.h"

NAMESPACE_SPHINCS

using Utility::IntegerTools;
using Utility::MemoryTools;

void SPXS192SHAKE::Generate(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	std::vector<uint> heights(SPX_TREE_HEIGHT + 1);
	std::vector<byte> stack((SPX_TREE_HEIGHT + 1) * SPX_N);
	std::vector<byte> authpath(SPX_TREE_HEIGHT * SPX_N);
	std::vector<byte> root(SPX_N);
	std::vector<byte> pkseed(SPX_N);
	std::vector<byte> skseed(SPX_N);
	std::vector<byte> stmp(3 * SPX_N);
	std::array<uint, 8> toptreeaddr = { 0 };

	SphincsUtils::SetLayerAddress(toptreeaddr, SPX_D - 1);
	SphincsUtils::SetType(toptreeaddr, SPX_ADDR_TYPE_HASHTREE);

	// generate the seed buffer
	Rng->Generate(stmp, 0, stmp.size());
	// copy to private and public keys
	MemoryTools::Copy(stmp, 0, PrivateKey, 0, stmp.size());
	MemoryTools::Copy(stmp, (2 * SPX_N), PublicKey, 0, SPX_N);
	// seeds for the hashing function
	MemoryTools::Copy(stmp, 0, skseed, 0, SPX_N);
	MemoryTools::Copy(stmp, 2 * SPX_N, pkseed, 0, SPX_N);

	// compute root node of the top-most subtree, and pass in the wots function prototype
	std::function<void(std::vector<byte> &,
		size_t,
		const std::vector<byte> &,
		const std::vector<byte> &,
		uint, std::array<uint, 8> &,
		size_t)> wotsgen = WOTS::WotsGenLeaf;

	SphincsUtils::TreeHash(root, 0, authpath, 0, skseed, pkseed, 0, 0, SPX_TREE_HEIGHT, toptreeaddr, stack, heights, SPX_N, wotsgen);
	// copy root and seeds to private key
	MemoryTools::Copy(root, 0, PublicKey, SPX_N, SPX_N);
	MemoryTools::Copy(root, 0, PrivateKey, 3 * SPX_N, SPX_N);
}

size_t SPXS192SHAKE::Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng)
{
	// returns an array containing the signature followed by the message

	std::vector<uint> heights(SPX_FORS_HEIGHT + 1);
	std::vector<byte> optrand(SPX_N);
	std::vector<byte> pk(2 * SPX_N);
	std::vector<byte> root(SPX_N);
	std::vector<byte> skseed(SPX_N);
	std::vector<byte> stack((SPX_FORS_HEIGHT + 1) * SPX_N);
	std::vector<byte> mhash(SPX_FORS_MSG_BYTES);
	std::vector<byte> skprf(SPX_N);
	std::array<uint, 8> treeaddr = { 0 };
	std::array<uint, 8> wotsaddr = { 0 };
	ulong tree;
	uint idx;
	uint idxsm;
	uint idxleaf;

	MemoryTools::Copy(PrivateKey, 0, skseed, 0, SPX_N);
	MemoryTools::Copy(PrivateKey, SPX_N, skprf, 0, SPX_N);
	MemoryTools::Copy(PrivateKey, 2 * SPX_N, pk, 0, 2 * SPX_N);
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
	FORS::GenMessageRandom(skprf, optrand, Signature, SPX_BYTES, Message.size(), SPX_N);
	// derive the message digest and leaf index from R, PK and M
	FORS::HashMessage(mhash, tree, idxleaf, Signature, pk, Signature, SPX_BYTES, Message.size(), SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_N);

	idxsm = SPX_N;
	SphincsUtils::SetTreeAddress(wotsaddr, tree);
	SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
	// sign the message hash using FORS
	FORS::ForsSign(Signature, idxsm, root, mhash, skseed, pk, wotsaddr, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_N);
	idxsm += SPX_FORS_BYTES;

	std::function<void(std::vector<byte> &,
		size_t,
		const std::vector<byte> &,
		const std::vector<byte> &,
		uint, std::array<uint, 8> &,
		size_t)> wotsgen = WOTS::WotsGenLeaf;

	for (idx = 0; idx < SPX_D; ++idx)
	{
		SphincsUtils::SetLayerAddress(treeaddr, idx);
		SphincsUtils::SetTreeAddress(treeaddr, tree);
		SphincsUtils::CopySubtreeAddress(treeaddr, wotsaddr);
		SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
		// compute a WOTS signature
		WOTS::WotsSign(Signature, idxsm, root, skseed, pk, wotsaddr, SPX_N);
		idxsm += SPX_WOTS_BYTES;

		// compute the authentication path for the used WOTS leaf
		SphincsUtils::TreeHash(root, 0, Signature, idxsm, skseed, pk, idxleaf, 0, SPX_TREE_HEIGHT, treeaddr, stack, heights, SPX_N, wotsgen);

		idxsm += SPX_TREE_HEIGHT * SPX_N;
		// update the indices for the next layer
		idxleaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
		tree = tree >> SPX_TREE_HEIGHT;
	}

	return SPX_BYTES + Message.size();
}

bool SPXS192SHAKE::Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey)
{
	// verifies a given signature-message pair under a given public key
	const size_t MSGLEN = Signature.size() - SPX_BYTES;
	std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + SPX_WOTS_LEN * SPX_N);
	std::vector<byte> leaf(SPX_N);
	std::vector<byte> mask(SPX_WOTS_LEN * SPX_N);
	std::vector<byte> pkroot(SPX_N);
	std::vector<byte> pkseed(SPX_N);
	std::vector<byte> root(SPX_N);
	std::vector<byte> sig(SPX_BYTES);
	std::vector<byte> tmsg(Signature.size());
	std::vector<byte> wotspk(SPX_WOTS_BYTES);
	std::vector<byte> mhash(SPX_FORS_MSG_BYTES);
	std::array<uint, 8> treeaddr = { 0 };
	std::array<uint, 8> wotsaddr = { 0 };
	std::array<uint, 8> wotspkaddr = { 0 };
	ulong tree;
	size_t idxsig;
	uint idx;
	uint idxleaf;
	bool res;

	res = false;

	if (Signature.size() >= SPX_BYTES)
	{
		// the API caller does not necessarily know what size a signature 
		// should be but SPHINCS+ signatures are always exactly SPX_BYTES.
		idxsig = 0;
		MemoryTools::Copy(PublicKey, SPX_N, pkroot, 0, SPX_N);
		MemoryTools::Copy(PublicKey, 0, pkseed, 0, SPX_N);
		SphincsUtils::SetType(wotsaddr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::SetType(treeaddr, SPX_ADDR_TYPE_HASHTREE);
		SphincsUtils::SetType(wotspkaddr, SPX_ADDR_TYPE_WOTSPK);

		// put the message all the way at the end of the message buffer, so that we can
		// prepend the required other inputs for the hash function
		MemoryTools::Copy(Signature, SPX_BYTES, tmsg, SPX_BYTES, MSGLEN);
		// create a copy of the signature so that m = sm is not an issue
		MemoryTools::Copy(Signature, 0, sig, 0, SPX_BYTES);
		// derive the message digest and leaf index from R || PK || M
		// the additional SPX_N is a result of the hash domain separator
		FORS::HashMessage(mhash, tree, idxleaf, sig, PublicKey, tmsg, SPX_BYTES, MSGLEN, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_N);
		idxsig += SPX_N;

		// layer correctly defaults to 0, so no need to set layer address
		SphincsUtils::SetTreeAddress(wotsaddr, tree);
		SphincsUtils::SetKeypairAddress(wotsaddr, idxleaf);
		FORS::ForsPkFromSig(root, 0, Signature, idxsig, mhash, pkseed, wotsaddr, SPX_FORS_HEIGHT, SPX_FORS_TREES, SPX_N);
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
			WOTS::WotsPkFromSig(wotspk, sig, idxsig, root, pkseed, wotsaddr, SPX_N);
			idxsig += SPX_WOTS_BYTES;
			// compute the leaf node using the WOTS public key
			SphincsUtils::THash(leaf, 0, wotspk, 0, SPX_WOTS_LEN, pkseed, wotspkaddr, buf, mask, SPX_N);
			// compute the root node of this subtree
			FORS::ComputeRoot(root, 0, leaf, idxleaf, 0, sig, idxsig, SPX_TREE_HEIGHT, pkseed, treeaddr, SPX_N);
			idxsig += SPX_TREE_HEIGHT * SPX_N;
			// update the indices for the next layer
			idxleaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
			tree = tree >> SPX_TREE_HEIGHT;
		}

		res = true;
	}

	// check if the root node equals the root node in the public key
	if (!IntegerTools::Compare(root, 0, pkroot, 0, SPX_N))
	{
		// if failed, zero the signature
		MemoryTools::Clear(tmsg, 0, tmsg.size());
		res = false;
	}

	// if verification was successful, resize and move the message
	Message.resize(MSGLEN);
	MemoryTools::Copy(tmsg, SPX_BYTES, Message, 0, MSGLEN);

	return res;
}

NAMESPACE_SPHINCSEND
