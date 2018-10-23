// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2018 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
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

#ifndef CEX_SPHINCSUTILS_H
#define CEX_SPHINCSUTILS_H

#include "CexDomain.h"
#include "sha3.h"
//#include "SHAKE.h"

NAMESPACE_SPHINCS

/// 
/// internal
/// 

/// <summary>
// An internal Sphincs+ utilities class
/// </summary>
class SphincsUtils
{
private:

/* Hash output length in bytes. */
#define SPX_N 16
/* Height of the hypertree. */
#define SPX_FULL_HEIGHT 60
/* Number of subtree layer. */
#define SPX_D 20
/* FORS tree dimensions. */
#define SPX_FORS_HEIGHT 9
#define SPX_FORS_TREES 30
/* Winternitz parameter, */
#define SPX_WOTS_W 16

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

   /* For clarity */
#define SPX_ADDR_BYTES 32

/* WOTS parameters. */
#if SPX_WOTS_W == 256
#define SPX_WOTS_LOGW 8
#elif SPX_WOTS_W == 16
#define SPX_WOTS_LOGW 4
#else
#error SPX_WOTS_W assumed 16 or 256
#endif

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#if SPX_WOTS_W == 256
#if SPX_N <= 1
#define SPX_WOTS_LEN2 1
#elif SPX_N <= 256
#define SPX_WOTS_LEN2 2
#else
#error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#endif
#elif SPX_WOTS_W == 16
#if SPX_N <= 8
#define SPX_WOTS_LEN2 2
#elif SPX_N <= 136
#define SPX_WOTS_LEN2 3
#elif SPX_N <= 256
#define SPX_WOTS_LEN2 4
#else
#error Did not precompute SPX_WOTS_LEN2 for n outside {2, .., 256}
#endif
#endif

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

#if SPX_TREE_HEIGHT * SPX_D != SPX_FULL_HEIGHT
#error SPX_D should always divide SPX_FULL_HEIGHT
#endif

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +\
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */

#define SPX_OPTRAND_BYTES 32
#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

public:

	// wots.c
	/**
	 * Computes the starting value for a chain, i.e. the secret key.
	 * Expects the address to be complete up to the chain address.
	 */
	static void wots_gen_sk(byte *sk, const byte *sk_seed, uint32_t wots_addr[8])
	{
		/* Make sure that the hash address is actually zeroed. */
		set_hash_addr(wots_addr, 0);

		/* Generate sk element. */
		prf_addr(sk, sk_seed, wots_addr);
	}

	/**
	 * Computes the chaining function.
	 * out and in have to be n-byte arrays.
	 *
	 * Interprets in as start-th value of the chain.
	 * addr has to contain the address of the chain.
	 */
	static void gen_chain(byte *out, const byte *in, uint start, uint steps, const byte *pub_seed, uint32_t addr[8])
	{
		uint32_t i;

		/* Initialize out with the value at position 'start'. */
		memcpy(out, in, SPX_N);

		/* Iterate 'steps' calls to the hash function. */
		for (i = start; i < (start + steps) && i < SPX_WOTS_W; i++) 
		{
			set_hash_addr(addr, i);
			thash(out, out, 1, pub_seed, addr);
		}
	}

	/**
	 * base_w algorithm as described in draft.
	 * Interprets an array of bytes as integers in base w.
	 * This only works when log_w is a divisor of 8.
	 */
	static void base_w(int *output, const int out_len, const byte *input)
	{
		int in = 0;
		int out = 0;
		byte total;
		int bits = 0;
		int consumed;

		for (consumed = 0; consumed < out_len; consumed++) 
		{
			if (bits == 0) 
			{
				total = input[in];
				in++;
				bits += 8;
			}
			bits -= SPX_WOTS_LOGW;
			output[out] = (total >> bits) & (SPX_WOTS_W - 1);
			out++;
		}
	}

	/* Computes the WOTS+ checksum over a message (in base_w). */
	static void wots_checksum(int *csum_base_w, const int *msg_base_w)
	{
		int csum = 0;
		byte csum_bytes[(SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];
		uint i;

		/* Compute checksum. */
		for (i = 0; i < SPX_WOTS_LEN1; i++) 
		{
			csum += SPX_WOTS_W - 1 - msg_base_w[i];
		}

		/* Convert checksum to base_w. */
		/* Make sure expected empty zero bits are the least significant bits. */
		csum = csum << (8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8));
		ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
		base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
	}

	/* Takes a message and derives the matching chain lengths. */
	static void chain_lengths(int *lengths, const byte *msg)
	{
		base_w(lengths, SPX_WOTS_LEN1, msg);
		wots_checksum(lengths + SPX_WOTS_LEN1, lengths);
	}

	/**
	 * WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
	 * elements and computes the corresponding public key.
	 * It requires the seed pub_seed (used to generate bitmasks and hash keys)
	 * and the address of this WOTS key pair.
	 *
	 * Writes the computed public key to 'pk'.
	 */
	static void wots_gen_pk(byte *pk, const byte *sk_seed, const byte *pub_seed, uint32_t addr[8])
	{
		uint32_t i;

		for (i = 0; i < SPX_WOTS_LEN; i++) 
		{
			set_chain_addr(addr, i);
			wots_gen_sk(pk + i * SPX_N, sk_seed, addr);
			gen_chain(pk + i * SPX_N, pk + i * SPX_N, 0, SPX_WOTS_W - 1, pub_seed, addr);
		}
	}

	/**
	 * Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'.
	 */
	static void wots_sign(byte *sig, const byte *msg, const byte *sk_seed, const byte *pub_seed, uint32_t addr[8])
	{
		int lengths[SPX_WOTS_LEN];
		uint32_t i;

		chain_lengths(lengths, msg);

		for (i = 0; i < SPX_WOTS_LEN; i++) 
		{
			set_chain_addr(addr, i);
			wots_gen_sk(sig + i * SPX_N, sk_seed, addr);
			gen_chain(sig + i * SPX_N, sig + i * SPX_N, 0, lengths[i], pub_seed, addr);
		}
	}

	/**
	 * Takes a WOTS signature and an n-byte message, computes a WOTS public key.
	 *
	 * Writes the computed public key to 'pk'.
	 */
	static void wots_pk_from_sig(byte *pk, const byte *sig, const byte *msg, const byte *pub_seed, uint32_t addr[8])
	{
		int lengths[SPX_WOTS_LEN];
		uint32_t i;

		chain_lengths(lengths, msg);

		for (i = 0; i < SPX_WOTS_LEN; i++) 
		{
			set_chain_addr(addr, i);
			gen_chain(pk + i * SPX_N, sig + i * SPX_N, lengths[i], SPX_WOTS_W - 1 - lengths[i], pub_seed, addr);
		}
	}

	// fors.c

	static void fors_gen_sk(byte *sk, const byte *sk_seed, uint32_t fors_leaf_addr[8])
	{
		prf_addr(sk, sk_seed, fors_leaf_addr);
	}

	static void fors_sk_to_leaf(byte *leaf, const byte *sk, const byte *pub_seed, uint32_t fors_leaf_addr[8])
	{
		thash(leaf, sk, 1, pub_seed, fors_leaf_addr);
	}

	static void fors_gen_leaf(byte *leaf, const byte *sk_seed, const byte *pub_seed, uint32_t addr_idx, const uint32_t fors_tree_addr[8])
	{
		uint32_t fors_leaf_adr[8] = { 0 };

		/* Only copy the parts that must be kept in fors_leaf_adr. */
		copy_keypair_addr(fors_leaf_adr, fors_tree_addr);
		set_type(fors_leaf_adr, SPX_ADDR_TYPE_FORSTREE);
		set_tree_index(fors_leaf_adr, addr_idx);

		fors_gen_sk(leaf, sk_seed, fors_leaf_adr);
		fors_sk_to_leaf(leaf, leaf, pub_seed, fors_leaf_adr);
	}

	/**
	 * Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 * Assumes indices has space for SPX_FORS_TREES integers.
	 */
	static void message_to_indices(uint32_t *indices, const byte *m)
	{
		uint i, j;
		uint offset = 0;

		for (i = 0; i < SPX_FORS_TREES; i++) 
		{
			indices[i] = 0;
			for (j = 0; j < SPX_FORS_HEIGHT; j++) 
			{
				indices[i] <<= 1;
				indices[i] ^= (m[offset >> 3] >> (offset & 0x7)) & 0x1;
				offset++;
			}
		}
	}

	/**
	 * Signs a message m, deriving the secret key from sk_seed and the FTS address.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 */
	static void fors_sign(byte *sig, byte *pk, const byte *m, const byte *sk_seed, const byte *pub_seed, const uint32_t fors_addr[8])
	{
		uint32_t indices[SPX_FORS_TREES];
		byte roots[SPX_FORS_TREES * SPX_N];
		uint32_t fors_tree_addr[8] = { 0 };
		uint32_t fors_pk_addr[8] = { 0 };
		uint32_t idx_offset;
		uint i;

		copy_keypair_addr(fors_tree_addr, fors_addr);
		copy_keypair_addr(fors_pk_addr, fors_addr);

		set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
		set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

		message_to_indices(indices, m);

		for (i = 0; i < SPX_FORS_TREES; i++) 
		{
			idx_offset = i * (1 << SPX_FORS_HEIGHT);

			set_tree_height(fors_tree_addr, 0);
			set_tree_index(fors_tree_addr, indices[i] + idx_offset);

			/* Include the secret key part that produces the selected leaf node. */
			fors_gen_sk(sig, sk_seed, fors_tree_addr);
			sig += SPX_N;

			/* Compute the authentication path for this leaf node. */
			treehash(roots + i * SPX_N, sig, sk_seed, pub_seed, indices[i], idx_offset, SPX_FORS_HEIGHT, fors_gen_leaf, fors_tree_addr);
			sig += SPX_N * SPX_FORS_HEIGHT;
		}

		/* Hash horizontally across all tree roots to derive the public key. */
		thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
	}

	/**
	 * Derives the FORS public key from a signature.
	 * This can be used for verification by comparing to a known public key, or to
	 * subsequently verify a signature on the derived public key. The latter is the
	 * typical use-case when used as an FTS below an OTS in a hypertree.
	 * Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
	 */
	static void fors_pk_from_sig(byte *pk, const byte *sig, const byte *m, const byte *pub_seed, const uint32_t fors_addr[8])
	{
		uint32_t indices[SPX_FORS_TREES];
		byte roots[SPX_FORS_TREES * SPX_N];
		byte leaf[SPX_N];
		uint32_t fors_tree_addr[8] = { 0 };
		uint32_t fors_pk_addr[8] = { 0 };
		uint32_t idx_offset;
		uint i;

		copy_keypair_addr(fors_tree_addr, fors_addr);
		copy_keypair_addr(fors_pk_addr, fors_addr);

		set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
		set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

		message_to_indices(indices, m);

		for (i = 0; i < SPX_FORS_TREES; i++) 
		{
			idx_offset = i * (1 << SPX_FORS_HEIGHT);

			set_tree_height(fors_tree_addr, 0);
			set_tree_index(fors_tree_addr, indices[i] + idx_offset);

			/* Derive the leaf from the included secret key part. */
			fors_sk_to_leaf(leaf, sig, pub_seed, fors_tree_addr);
			sig += SPX_N;

			/* Derive the corresponding root node of this tree. */
			compute_root(roots + i * SPX_N, leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT, pub_seed, fors_tree_addr);
			sig += SPX_N * SPX_FORS_HEIGHT;
		}

		/* Hash horizontally across all tree roots to derive the public key. */
		thash(pk, roots, SPX_FORS_TREES, pub_seed, fors_pk_addr);
	}

	// utils.c

	/**
	 * Converts the value of 'in' to 'outlen' bytes in big-endian byte order.
	 */
	static void ull_to_bytes(byte *out, uint outlen, unsigned long long in)
	{
		int i;

		/* Iterate over out in decreasing order, for big-endianness. */
		for (i = outlen - 1; i >= 0; i--) 
		{
			out[i] = in & 0xff;
			in = in >> 8;
		}
	}

	/**
	 * Converts the inlen bytes in 'in' from big-endian byte order to an integer.
	 */
	static unsigned long long bytes_to_ull(const byte *in, uint inlen)
	{
		unsigned long long retval = 0;
		uint i;

		for (i = 0; i < inlen; i++) 
		{
			retval |= ((unsigned long long)in[i]) << (8 * (inlen - 1 - i));
		}
		return retval;
	}

	/**
	 * Computes a root node given a leaf and an auth path.
	 * Expects address to be complete other than the tree_height and tree_index.
	 */
	static void compute_root(byte *root, const byte *leaf, unsigned long leafidx, uint32_t idx_offset, const byte *auth_path, uint32_t tree_height, const byte *pub_seed, uint32_t addr[8])
	{
		uint32_t i;
		byte buffer[2 * SPX_N];

		/* If leafidx is odd (last bit = 1), current path element is a right child
		   and auth_path has to go left. Otherwise it is the other way around. */
		if (leafidx & 1) 
		{
			memcpy(buffer + SPX_N, leaf, SPX_N);
			memcpy(buffer, auth_path, SPX_N);
		}
		else 
		{
			memcpy(buffer, leaf, SPX_N);
			memcpy(buffer + SPX_N, auth_path, SPX_N);
		}
		auth_path += SPX_N;

		for (i = 0; i < tree_height - 1; i++) 
		{
			leafidx >>= 1;
			idx_offset >>= 1;
			/* Set the address of the node we're creating. */
			set_tree_height(addr, i + 1);
			set_tree_index(addr, leafidx + idx_offset);

			/* Pick the right or left neighbor, depending on parity of the node. */
			if (leafidx & 1) 
			{
				thash(buffer + SPX_N, buffer, 2, pub_seed, addr);
				memcpy(buffer, auth_path, SPX_N);
			}
			else 
			{
				thash(buffer, buffer, 2, pub_seed, addr);
				memcpy(buffer + SPX_N, auth_path, SPX_N);
			}
			auth_path += SPX_N;
		}

		/* The last iteration is exceptional; we do not copy an auth_path node. */
		leafidx >>= 1;
		idx_offset >>= 1;
		set_tree_height(addr, tree_height);
		set_tree_index(addr, leafidx + idx_offset);
		thash(root, buffer, 2, pub_seed, addr);
	}

	/**
	 * For a given leaf index, computes the authentication path and the resulting
	 * root node using Merkle's TreeHash algorithm.
	 * Expects the layer and tree parts of the tree_addr to be set, as well as the
	 * tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
	 * Applies the offset idx_offset to indices before building addresses, so that
	 * it is possible to continue counting indices across trees.
	 */
	static void treehash(byte *root, byte *auth_path, const byte *sk_seed, const byte *pub_seed, uint32_t leaf_idx, uint32_t idx_offset, uint32_t tree_height,
		void(*gen_leaf)(byte* /* leaf */, const byte* /* sk_seed */, const byte* /* pub_seed */, uint32_t /* addr_idx */, const uint32_t[8] /* tree_addr */), uint32_t tree_addr[8])
	{
		std::vector<byte> stack((tree_height + 1)*SPX_N);
		//byte stack[(tree_height + 1)*SPX_N];
		std::vector<int> heights(tree_height + 1);
		//uint heights[tree_height + 1];
		uint offset = 0;
		uint32_t idx;
		uint32_t tree_idx;

		for (idx = 0; idx < (uint32_t)(1 << tree_height); idx++) 
		{
			/* Add the next leaf node to the stack. */
			gen_leaf(stack.data() + offset * SPX_N, sk_seed, pub_seed, idx + idx_offset, tree_addr);
			offset++;
			heights[offset - 1] = 0;

			/* If this is a node we need for the auth path.. */
			if ((leaf_idx ^ 0x1) == idx) 
			{
				memcpy(auth_path, stack.data() + (offset - 1)*SPX_N, SPX_N);
			}

			/* While the top-most nodes are of equal height.. */
			while (offset >= 2 && heights[offset - 1] == heights[offset - 2]) 
			{
				/* Compute index of the new node, in the next layer. */
				tree_idx = (idx >> (heights[offset - 1] + 1));

				/* Set the address of the node we're creating. */
				set_tree_height(tree_addr, heights[offset - 1] + 1);
				set_tree_index(tree_addr, tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
				/* Hash the top-most nodes from the stack together. */
				thash(stack.data() + (offset - 2)*SPX_N, stack.data() + (offset - 2)*SPX_N, 2, pub_seed, tree_addr);
				offset--;
				/* Note that the top-most node is now one layer higher. */
				heights[offset - 1]++;

				/* If this is a node we need for the auth path.. */
				if (((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx) 
				{
					memcpy(auth_path + heights[offset - 1] * SPX_N, stack.data() + (offset - 1)*SPX_N, SPX_N);
				}
			}
		}
		memcpy(root, stack.data(), SPX_N);
	}

	// hash_address.c
	static void set_layer_addr(uint32_t addr[8], uint32_t layer)
	{
		addr[0] = layer;
	}

	static void set_tree_addr(uint32_t addr[8], uint64_t tree)
	{
		addr[1] = 0;
		addr[2] = (uint32_t)(tree >> 32);
		addr[3] = (uint32_t)tree;
	}

	static void set_type(uint32_t addr[8], uint32_t type)
	{
		addr[4] = type;
	}

	static void copy_subtree_addr(uint32_t out[8], const uint32_t in[8])
	{
		out[0] = in[0];
		out[1] = in[1];
		out[2] = in[2];
		out[3] = in[3];
	}

	/* These functions are used for OTS addresses. */

	static void set_keypair_addr(uint32_t addr[8], uint32_t keypair)
	{
		addr[5] = keypair;
	}

	static void copy_keypair_addr(uint32_t out[8], const uint32_t in[8])
	{
		out[0] = in[0];
		out[1] = in[1];
		out[2] = in[2];
		out[3] = in[3];
		out[5] = in[5];
	}

	static void set_chain_addr(uint32_t addr[8], uint32_t chain)
	{
		addr[6] = chain;
	}

	static void set_hash_addr(uint32_t addr[8], uint32_t hash)
	{
		addr[7] = hash;
	}

	/* These functions are used for all hash tree addresses (including FORS). */

	static void set_tree_height(uint32_t addr[8], uint32_t tree_height)
	{
		addr[6] = tree_height;
	}

	static void set_tree_index(uint32_t addr[8], uint32_t tree_index)
	{
		addr[7] = tree_index;
	}

	// hash_shake256.c
	static void addr_to_bytes(byte *bytes, const uint32_t addr[8])
	{
		int i;

		for (i = 0; i < 8; i++) 
		{
			ull_to_bytes(bytes + i * 4, 4, addr[i]);
		}
	}

	/* For SHAKE256, there is no immediate reason to initialize at the start,
	   so this function is an empty operation. */
	static void initialize_hash_function(const byte *pub_seed, const byte *sk_seed)
	{
		(void)pub_seed; /* Suppress an 'unused parameter' warning. */
		(void)sk_seed; /* Suppress an 'unused parameter' warning. */
	}

	/*
	 * Computes PRF(key, addr), given a secret key of SPX_N bytes and an address
	 */
	static void prf_addr(byte *out, const byte *key, const uint32_t addr[8])
	{
		//std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES);
		//std::vector<byte> otp(SPX_N);
		byte buf[SPX_N + SPX_ADDR_BYTES];

		memcpy(buf, key, SPX_N);
		addr_to_bytes(buf + SPX_N, addr);

		/*Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
		gen.Initialize(buf);
		gen.Generate(otp);
		memcpy(out, otp.data(), SPX_N);*/

		shake256(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
	}

	/**
	 * Computes the message-dependent randomness R, using a secret seed and an
	 * optional randomization value prefixed to the message.
	 * This requires m to have at least 2*SPX_N bytes * bytes of space available in
	 * front of the pointer, i.e. before the message to use for the prefix. This is
	 * necessary to prevent having to move the message around (and allocate memory
	 * for it).
	 */
	static void gen_message_random(byte *R, const byte *sk_prf, const byte *optrand, byte *m, ulong mlen)
	{
		memcpy(m - 2 * SPX_N, sk_prf, SPX_N);
		memcpy(m - SPX_N, optrand, SPX_N);

		/*Kdf::SHAKE gen(Enumeration::ShakeModes::SHAKE256);
		std::vector<byte> k(SPX_N + SPX_ADDR_BYTES);
		std::vector<byte> otp(SPX_N);*/

		shake256(R, SPX_N, m - 2 * SPX_N, mlen + 2 * SPX_N);
	}

	/**
	 * Computes the message hash using R, the public key, and the message.
	 * Notably, it requires m to have SPX_N + SPX_PK_BYTES bytes of space available
	 * in front of the pointer, i.e. before the message, to use for the prefix.
	 * This is necessary to prevent having to move the * message around (and
	 * allocate memory for it).
	 * Outputs the message digest and the index of the leaf. The index is split in
	 * the tree index and the leaf index, for convenient copying to an address.
	 */
	static void hash_message(byte *digest, uint64_t *tree, uint32_t *leaf_idx, const byte *R, const byte *pk, byte *m, unsigned long long mlen)
	{
#define SPX_TREE_BITS (SPX_TREE_HEIGHT * (SPX_D - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS SPX_TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES)

		byte buf[SPX_DGST_BYTES];
		byte *bufp = buf;

		memcpy(m - SPX_N - SPX_PK_BYTES, R, SPX_N);
		memcpy(m - SPX_PK_BYTES, pk, SPX_PK_BYTES);

		shake256(buf, SPX_DGST_BYTES, m - SPX_N - SPX_PK_BYTES, mlen + SPX_N + SPX_PK_BYTES);

		memcpy(digest, bufp, SPX_FORS_MSG_BYTES);
		bufp += SPX_FORS_MSG_BYTES;

#if SPX_TREE_BITS > 64
#error For given height and depth, 64 bits cannot represent all subtrees
#endif

		*tree = bytes_to_ull(bufp, SPX_TREE_BYTES);
		*tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
		bufp += SPX_TREE_BYTES;

		*leaf_idx = bytes_to_ull(bufp, SPX_LEAF_BYTES);
		*leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
	}

	/**
	 * Takes an array of inblocks concatenated arrays of SPX_N bytes.
	 */
	static void thash(byte *out, const byte *in, uint inblocks, const byte *pub_seed, uint32_t addr[8])
	{
		std::vector<byte> buf(SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
		//byte buf[SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N];
		std::vector<byte> bitmask(inblocks * SPX_N);
		//byte bitmask[inblocks * SPX_N];
		uint i;

		memcpy(buf.data(), pub_seed, SPX_N);
		addr_to_bytes(buf.data() + SPX_N, addr);

		shake256(bitmask.data(), inblocks * SPX_N, buf.data(), SPX_N + SPX_ADDR_BYTES);

		for (i = 0; i < inblocks * SPX_N; i++) 
		{
			buf[SPX_N + SPX_ADDR_BYTES + i] = in[i] ^ bitmask[i];
		}

		shake256(out, SPX_N, buf.data(), SPX_N + SPX_ADDR_BYTES + inblocks * SPX_N);
	}
};

NAMESPACE_SPHINCSEND
#endif
