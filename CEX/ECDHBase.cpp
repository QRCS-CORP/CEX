#include "ECDHBase.h"
#include "MemoryTools.h"

NAMESPACE_ECDH

using Tools::MemoryTools;

bool ECDHBase::Ed25519KeyExchange(std::vector<uint8_t> &Secret, const std::vector<uint8_t> &PublicKey, const std::vector<uint8_t> &PrivateKey)
{
	bool res;

	res = (EC25519::ScalarMultCurve25519(Secret, PrivateKey, PublicKey) == 0);

	return res;
}

void ECDHBase::Ed25519GenerateKeyPair(std::vector<uint8_t> &PublicKey, std::vector<uint8_t> &PrivateKey, const std::vector<uint8_t> &Seed, std::unique_ptr<IDigest> &Digest)
{
	std::vector<uint8_t> tseed(64);

	Digest->Compute(Seed, tseed);
	MemoryTools::Copy(tseed, 0, PrivateKey, 0, EC25519::EC25519_SEED_SIZE);
	EC25519::ScalarmultCurve25519Ref10Base(PublicKey, PrivateKey);
}

NAMESPACE_ECDHEND