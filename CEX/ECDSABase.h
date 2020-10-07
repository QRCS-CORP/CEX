#include "CexDomain.h"
#include "EC25519.h"
#include "IDigest.h"

NAMESPACE_ECDSA

using Digest::IDigest;
using Asymmetric::Encrypt::ECDH::EC25519;

class ECDSABase
{
public:

	static void GenerateKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, std::vector<byte> &Seed, std::unique_ptr<IDigest> &Digest);
	static bool Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<IDigest> &Digest);
	static bool Verify(std::vector<byte> &Message, const std::vector<byte> &Signature, const std::vector<byte> &PublicKey, std::unique_ptr<IDigest> &Digest);

private:

	static bool Ed25519Sign(std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PrivateKey, std::unique_ptr<IDigest> &Digest);
	static bool Ed25519Verify(const std::vector<byte> &Signature, const std::vector<byte> &Message, const std::vector<byte> &PublicKey, std::unique_ptr<IDigest> &Digest);
};

NAMESPACE_ECDSAEND