#include "Sphincs.h"
#include "SecureRandom.h"
#include "SHAKE256F128.h"

NAMESPACE_SPHINCS

Sphincs::Sphincs()
{
}

Sphincs::~Sphincs()
{
}

const AsymmetricEngines Sphincs::Enumeral()
{
	return AsymmetricEngines::Sphincs;
}

const bool Sphincs::IsInitialized()
{
	return false;
}

const bool Sphincs::IsSigner()
{
	return false;
}

const std::string Sphincs::Name()
{
	return std::string("");
}


IAsymmetricKeyPair* Sphincs::Generate()
{
	return nullptr;
}

const void Sphincs::Initialize(IAsymmetricKey &AsymmetricKey)
{

}

void Sphincs::Reset()
{

}

void Sphincs::Sign(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Output, size_t OutOffset)
{

}

bool Sphincs::Verify(std::vector<byte> &Input, size_t InOffset, size_t Length, std::vector<byte> &Code)
{
	return false;
}

void Sphincs::Test()
{
	const size_t MLEN = 3300;
	std::vector<byte> pk(CRYPTO_PUBLICKEYBYTES);
	std::vector<byte> sk(CRYPTO_SECRETKEYBYTES);
	std::vector<byte> m(MLEN);
	std::vector<byte> m1(MLEN);
	std::vector<byte> sm(MLEN + CRYPTO_BYTES);

	Prng::SecureRandom rng;
	rng.Generate(m);

	size_t smlen = 0;
	size_t mlen = 0;
	size_t mlen1 = 0;
	int ret = 0;
	size_t ctr = 0;

	SHAKE256F128 cpr;

	cpr.crypto_sign_keypair(pk.data(), sk.data());

	cpr.crypto_sign(sm.data(), &smlen, m.data(), m.size(), sk.data());

	ret = cpr.crypto_sign_open(m1.data(), &mlen1, sm.data(), smlen, pk.data());

	if (ret != 0)
	{
		throw;
	}
}

NAMESPACE_SPHINCSEND