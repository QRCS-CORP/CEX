#include "CexDomain.h"
#include "EC25519.h"
#include "IDigest.h"

NAMESPACE_ECDH

using Asymmetric::Encrypt::ECDH::EC25519;
using Digest::IDigest;

class ECDHBase
{
public:

	static bool Ed25519KeyExchange(std::vector<uint8_t> &Secret, const std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &PrivateKey);
	static void Ed25519GenerateKeyPair(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, const std::vector<uint8_t> &Seed, std::unique_ptr<IDigest> &Digest);
};

NAMESPACE_ECDHEND