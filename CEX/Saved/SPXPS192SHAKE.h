#ifndef CEX_SPXS192SHAKE_H
#define CEX_SPXS192SHAKE_H

#include "CexConfig.h"
#include "IPrng.h"
#include <functional>

NAMESPACE_SPHINCSPLUS

/// <summary>
/// The SphincsPlus+ small 192bit support class
/// </summary>
class SPXPS192SHAKE
{
private:

	// hash output length in bytes
	static const size_t SPX_N = 24;
	// height of the hypertree
	static const size_t SPX_FULL_HEIGHT = 63;
	// number of subtree layer
	static const size_t SPX_D = 7;
	// SPXPFORS tree dimensions
	static const size_t SPX_FORS_HEIGHT = 14;
	static const size_t SPX_FORS_TREES = 17;
	// Winternitz parameter
	static const size_t SPX_WOTS_W = 16;
	static const size_t SPX_ADDR_BYTES = 32;
	// SPXPWOTS parameters
	static const size_t SPX_WOTS_LOGW = 4;
	static const size_t SPX_WOTS_LEN1 = (8 * SPX_N / SPX_WOTS_LOGW);
	// SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1 precomputation
	static const size_t SPX_WOTS_LEN2 = 3;
	static const size_t SPX_WOTS_LEN = (SPX_WOTS_LEN1 + SPX_WOTS_LEN2);
	static const size_t SPX_WOTS_BYTES = (SPX_WOTS_LEN * SPX_N);
	static const size_t SPX_WOTS_PK_BYTES = SPX_WOTS_BYTES;
	// subtree size
	static const size_t SPX_TREE_HEIGHT = (SPX_FULL_HEIGHT / SPX_D);
	// SPXPFORS parameters
	static const size_t SPX_FORS_MSG_BYTES = ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8);
	static const size_t SPX_FORS_BYTES = ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N);
	static const size_t SPX_FORS_PK_BYTES = SPX_N;
	// resulting SPX sizes
	static const size_t SPX_BYTES = (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N);
	static const size_t SPX_PK_BYTES = (2 * SPX_N);
	static const size_t SPX_SK_BYTES = (2 * SPX_N + SPX_PK_BYTES);
	// optionally, signing can be made non-deterministic using optrand.
	// this can help counter side-channel attacks that would benefit from
	// getting a large number of traces when the signer uses the same nodes
	static const size_t SPX_OPTRAND_BYTES = 32;
	static const size_t SPX_ADDR_TYPE_WOTS = 0;
	static const size_t SPX_ADDR_TYPE_WOTSPK = 1;
	static const size_t SPX_ADDR_TYPE_HASHTREE = 2;
	static const size_t SPX_ADDR_TYPE_FORSTREE = 3;
	static const size_t SPX_ADDR_TYPE_FORSPK = 4;

public:

	/// <summary>
	/// The Public Key size
	/// </summary>
	static const size_t SPHINCS_PUBLICKEY_SIZE = SPX_PK_BYTES;

	/// <summary>
	/// The Private Key size
	/// </summary>
	static const size_t SPHINCS_SECRETKEY_SIZE = SPX_SK_BYTES;

	/// <summary>
	/// The base Signature size
	/// </summary>
	static const size_t SPHINCS_SIGNATURE_SIZE = SPX_BYTES;

private:

public:

	static void Generate(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	static size_t Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<Prng::IPrng> &Rng);

	static bool Verify(std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey);
};

NAMESPACE_SPHINCSEND
#endif
