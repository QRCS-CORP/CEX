#include "CexDomain.h"
#include "EC25519.h"
#include "IDigest.h"

NAMESPACE_ECDSA

using Digest::IDigest;
using Asymmetric::Encrypt::ECDH::EC25519;

class ECDSABase
{
public:

	static void GenerateKeyPair(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, std::vector<uint8_t> &Seed, std::unique_ptr<IDigest> &Digest);
	static bool Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<IDigest> &Digest);
	static bool Verify(std::vector<uint8_t> &Message, const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &PublicKey, std::unique_ptr<IDigest> &Digest);

private:

	static bool Ed25519Sign(std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PrivateKey, std::unique_ptr<IDigest> &Digest);
	static bool Ed25519Verify(const std::vector<uint8_t> &Signature, const std::vector<uint8_t> &Message, const std::vector<uint8_t> &PublicKey, std::unique_ptr<IDigest> &Digest);
};

NAMESPACE_ECDSAEND