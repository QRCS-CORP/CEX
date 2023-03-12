#ifndef CEXTEST_NISTPQPARSER_H
#define CEXTEST_NISTPQPARSER_H

#include "TestCommon.h"
#include "../CEX/AsymmetricParameters.h"

namespace Test
{
	using CEX::Enumeration::AsymmetricParameters;

	class NistPqParser final
	{
private:

	static const std::string COUNT_TOKEN;
	static const std::string SEED_TOKEN;
	static const std::string PUBLIC_KEY_TOKEN;
	static const std::string PRIVATE_KEY_TOKEN;
	static const std::string CIPHERTEXT_TOKEN;
	static const std::string SHARED_SECRET_TOKEN;
	static const std::string MESSAGE_TOKEN;
	static const std::string MESSAGE_LENGTH_TOKEN;
	static const std::string SIGNED_MESSAGE_TOKEN;
	static const std::string SIGNED_MESSAGE_LENGTH_TOKEN;

public:

	static void ParseNistCipherKat(const std::string &FilePath,
		std::vector<uint8_t> &Seed, size_t *SeedLength,
		std::vector<uint8_t> &PublicKey, size_t *PublickeyLength,
		std::vector<uint8_t> &PrivateKey, size_t *PrivateKeyLength,
		std::vector<uint8_t> &CipherText, size_t *CipherTextLength,
		std::vector<uint8_t> &SharedSecret, size_t *SharedSecretLength,
		uint32_t SetNumber);

	static void ParseNistSignatureKat(const std::string &FilePath,
		std::vector<uint8_t> &Seed, size_t* SeedLength,
		std::vector<uint8_t> &Message, size_t* MessageLength,
		std::vector<uint8_t> &PublicKey, size_t* PublickeyLength,
		std::vector<uint8_t> &PrivateKey, size_t* PrivateKeyLength,
		std::vector<uint8_t> &SignedMessage, size_t* SignedMessageLength,
		uint32_t SetNumber);
	};
}
#endif