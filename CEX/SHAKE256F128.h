#ifndef CEX_SHAKE256F128_H
#define CEX_SHAKE256F128_H

#include "CexDomain.h"
#include "SecureRandom.h"
#include "SphincsUtils.h"
#include <string.h>
#include <stdint.h>
#include "../CEX/Sphincs/sha3.h"
//#include "../CEX/Sphincs/api.h"
//#include "../CEX/Sphincs/params.h"
//#include "../CEX/Sphincs/wots.h"
//#include "../CEX/Sphincs/fors.h"
//#include "../CEX/Sphincs/hash.h"
//#include "../CEX/Sphincs/hash_address.h"
//#include "../CEX/Sphincs/rng.h"
//#include "../CEX/Sphincs/utils.h"

NAMESPACE_SPHINCS

/// <summary>
/// The Asymmetric cipher interface
/// </summary>
class SHAKE256F128
{
public:

#define CRYPTO_SECRETKEYBYTES SPX_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES SPX_PK_BYTES
#define CRYPTO_BYTES SPX_BYTES

	/**
	 * Computes the leaf at a given address. First generates the WOTS key pair,
	 * then computes leaf by hashing horizontally.
	 */
	static void wots_gen_leaf(byte *leaf, const byte *sk_seed, const byte *pub_seed, uint32_t addr_idx, const uint32_t tree_addr[8])
	{
		byte pk[SPX_WOTS_BYTES];
		uint32_t wots_addr[8] = { 0 };
		uint32_t wots_pk_addr[8] = { 0 };

		SphincsUtils::set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

		SphincsUtils::copy_subtree_addr(wots_addr, tree_addr);
		SphincsUtils::set_keypair_addr(wots_addr, addr_idx);
		SphincsUtils::wots_gen_pk(pk, sk_seed, pub_seed, wots_addr);

		SphincsUtils::copy_keypair_addr(wots_pk_addr, wots_addr);
		SphincsUtils::thash(leaf, pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);
	}

	/*
	 * Generates an SPX key pair.
	 * Format sk: [SK_SEED || SK_PRF || PUB_SEED || root]
	 * Format pk: [PUB_SEED || root]
	 */
	int crypto_sign_keypair(byte *pk, byte *sk)
	{
		/* We do not need the auth path in key generation, but it simplifies the
		   code to have just one treehash routine that computes both root and path
		   in one function. */
		byte auth_path[SPX_TREE_HEIGHT * SPX_N];
		uint32_t top_tree_addr[8] = { 0 };

		SphincsUtils::set_layer_addr(top_tree_addr, SPX_D - 1);
		SphincsUtils::set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE);

		/* Initialize SK_SEED, SK_PRF and PUB_SEED. */
		randombytes(sk, 3 * SPX_N);

		memcpy(pk, sk + 2 * SPX_N, SPX_N);

		/* This hook allows the hash function instantiation to do whatever
		   preparation or computation it needs, based on the public seed. */
		SphincsUtils::initialize_hash_function(pk, sk);

		/* Compute root node of the top-most subtree. */
		SphincsUtils::treehash(sk + 3 * SPX_N, auth_path, sk, sk + 2 * SPX_N, 0, 0, SPX_TREE_HEIGHT, wots_gen_leaf, top_tree_addr);

		memcpy(pk + SPX_N, sk + 3 * SPX_N, SPX_N);

		return 0;
	}

	void randombytes(byte* buf, size_t len)
	{
		Prng::SecureRandom rnd(Enumeration::Prngs::BCR, Enumeration::Providers::CSP);
		std::vector<byte> tmp(len);
		rnd.Generate(tmp);
		memcpy(buf, tmp.data(), len);
	}

	/**
	 * Returns an array containing the signature followed by the message.
	 */
	int crypto_sign(byte *sm, size_t *smlen, const byte *m, size_t mlen, const byte *sk)
	{
		const byte *sk_seed = sk;
		const byte *sk_prf = sk + SPX_N;
		const byte *pk = sk + 2 * SPX_N;
		const byte *pub_seed = pk;

		byte optrand[SPX_N];
		byte mhash[SPX_FORS_MSG_BYTES];
		byte root[SPX_N];
		ulong i;
		uint64_t tree;
		uint32_t idx_leaf;
		uint32_t wots_addr[8] = { 0 };
		uint32_t tree_addr[8] = { 0 };

		// This hook allows the hash function instantiation to do whatever
		// preparation or computation it needs, based on the public seed.
		SphincsUtils::initialize_hash_function(pub_seed, sk_seed);
		SphincsUtils::set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);

		// Already put the message in the right place, to make it easier to prepend
		// things when computing the hash over the message.
		// We need to do this from back to front, so that it works when sm = m
		for (i = mlen; i > 0; i--) 
		{
			sm[SPX_BYTES + i - 1] = m[i - 1];
		}

		*smlen = SPX_BYTES + mlen;

		// Optionally, signing can be made non-deterministic using optrand.
		// This can help counter side-channel attacks that would benefit from
		// getting a large number of traces when the signer uses the same nodes.
		randombytes(optrand, SPX_N);
		// Compute the digest randomization value.
		SphincsUtils::gen_message_random(sm, sk_prf, optrand, sm + SPX_BYTES, mlen);

		// Derive the message digest and leaf index from R, PK and M.
		SphincsUtils::hash_message(mhash, &tree, &idx_leaf, sm, pk, sm + SPX_BYTES, mlen);
		sm += SPX_N;

		SphincsUtils::set_tree_addr(wots_addr, tree);
		SphincsUtils::set_keypair_addr(wots_addr, idx_leaf);

		// Sign the message hash using FORS.
		SphincsUtils::fors_sign(sm, root, mhash, sk_seed, pub_seed, wots_addr);
		sm += SPX_FORS_BYTES;

		for (i = 0; i < SPX_D; i++) 
		{
			SphincsUtils::set_layer_addr(tree_addr, i);
			SphincsUtils::set_tree_addr(tree_addr, tree);

			SphincsUtils::copy_subtree_addr(wots_addr, tree_addr);
			SphincsUtils::set_keypair_addr(wots_addr, idx_leaf);

			// Compute a WOTS signature.
			SphincsUtils::wots_sign(sm, root, sk_seed, pub_seed, wots_addr);
			sm += SPX_WOTS_BYTES;

			// Compute the authentication path for the used WOTS leaf.
			SphincsUtils::treehash(root, sm, sk_seed, pub_seed, idx_leaf, 0, SPX_TREE_HEIGHT, wots_gen_leaf, tree_addr);
			sm += SPX_TREE_HEIGHT * SPX_N;

			// Update the indices for the next layer.
			idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
			tree = tree >> SPX_TREE_HEIGHT;
		}

		return 0;
	}

	/**
	 * Verifies a given signature-message pair under a given public key.
	 */
	int crypto_sign_open(byte *m, size_t *mlen, const byte *sm, size_t smlen, const byte *pk)
	{
		const byte *pub_seed = pk;
		const byte *pub_root = pk + SPX_N;
		byte mhash[SPX_FORS_MSG_BYTES];
		byte wots_pk[SPX_WOTS_BYTES];
		byte root[SPX_N];
		byte leaf[SPX_N];
		byte sig[SPX_BYTES];
		byte *sigptr = sig;
		uint i;
		uint64_t tree;
		uint32_t idx_leaf;
		uint32_t wots_addr[8] = { 0 };
		uint32_t tree_addr[8] = { 0 };
		uint32_t wots_pk_addr[8] = { 0 };

		/* This hook allows the hash function instantiation to do whatever
		   preparation or computation it needs, based on the public seed. */
		SphincsUtils::initialize_hash_function(pub_seed, NULL);

		SphincsUtils::set_type(wots_addr, SPX_ADDR_TYPE_WOTS);
		SphincsUtils::set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE);
		SphincsUtils::set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

		*mlen = smlen - SPX_BYTES;

		/* Put the message all the way at the end of the m buffer, so that we can
		 * prepend the required other inputs for the hash function. */
		memcpy(m + SPX_BYTES, sm + SPX_BYTES, *mlen);

		/* Create a copy of the signature so that m = sm is not an issue */
		memcpy(sig, sm, SPX_BYTES);

		/* Derive the message digest and leaf index from R || PK || M. */
		/* The additional SPX_N is a result of the hash domain separator. */
		SphincsUtils::hash_message(mhash, &tree, &idx_leaf, sigptr, pk, m + SPX_BYTES, *mlen);
		sigptr += SPX_N;

		/* Layer correctly defaults to 0, so no need to set_layer_addr */
		SphincsUtils::set_tree_addr(wots_addr, tree);
		SphincsUtils::set_keypair_addr(wots_addr, idx_leaf);

		SphincsUtils::fors_pk_from_sig(root, sigptr, mhash, pub_seed, wots_addr);
		sigptr += SPX_FORS_BYTES;

		/* For each subtree.. */
		for (i = 0; i < SPX_D; i++) 
		{
			SphincsUtils::set_layer_addr(tree_addr, i);
			SphincsUtils::set_tree_addr(tree_addr, tree);

			SphincsUtils::copy_subtree_addr(wots_addr, tree_addr);
			SphincsUtils::set_keypair_addr(wots_addr, idx_leaf);

			SphincsUtils::copy_keypair_addr(wots_pk_addr, wots_addr);

			/* The WOTS public key is only correct if the signature was correct. */
			/* Initially, root is the FORS pk, but on subsequent iterations it is
			   the root of the subtree below the currently processed subtree. */
			SphincsUtils::wots_pk_from_sig(wots_pk, sigptr, root, pub_seed, wots_addr);
			sigptr += SPX_WOTS_BYTES;

			/* Compute the leaf node using the WOTS public key. */
			SphincsUtils::thash(leaf, wots_pk, SPX_WOTS_LEN, pub_seed, wots_pk_addr);

			/* Compute the root node of this subtree. */
			SphincsUtils::compute_root(root, leaf, idx_leaf, 0, sigptr, SPX_TREE_HEIGHT, pub_seed, tree_addr);
			sigptr += SPX_TREE_HEIGHT * SPX_N;

			/* Update the indices for the next layer. */
			idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1));
			tree = tree >> SPX_TREE_HEIGHT;
		}

		/* Check if the root node equals the root node in the public key. */
		if (memcmp(root, pub_root, SPX_N)) 
		{
			/* If not, zero the message */
			memset(m, 0, *mlen);
			*mlen = 0;
			return -1;
		}

		/* If verification was successful, move the message to the right place. */
		memmove(m, m + SPX_BYTES, *mlen);

		return 0;
	}
};

NAMESPACE_SPHINCSEND
#endif