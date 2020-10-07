#include "ECDHBase.h"
#include "MemoryTools.h"

NAMESPACE_ECDH

using Tools::MemoryTools;

bool ECDHBase::Ed25519KeyExchange(std::vector<byte> &Secret, const std::vector<byte> &PublicKey, const std::vector<byte> &PrivateKey)
{
	bool res;

	res = (EC25519::ScalarMultCurve25519(Secret, PrivateKey, PublicKey) == 0);

	return res;
}

void ECDHBase::Ed25519GenerateKeyPair(std::vector<byte> &PublicKey, std::vector<byte> &PrivateKey, const std::vector<byte> &Seed, std::unique_ptr<IDigest> &Digest)
{
	std::vector<byte> tseed(64);

	Digest->Compute(Seed, tseed);
	MemoryTools::Copy(tseed, 0, PrivateKey, 0, EC25519::EC25519_SEED_SIZE);
	EC25519::ScalarmultCurve25519Ref10Base(PublicKey, PrivateKey);
}

NAMESPACE_ECDHEND