#include "CexDomain.h"
#include "EC25519.h"
#include "IDigest.h"

NAMESPACE_ECDH

using Asymmetric::Encrypt::ECDH::EC25519;
using Digest::IDigest;

class ECDHBase
{
public:

	static bool Ed25519KeyExchange(std::vector<byte> &Secret, const std::vector<byte> &PublicKey, const std::vector<byte> &PrivateKey);
	static void Ed25519GenerateKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, const std::vector<byte> &Seed, std::unique_ptr<IDigest> &Digest);
};

NAMESPACE_ECDHEND