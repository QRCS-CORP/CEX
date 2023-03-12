#include "NistPqParser.h"
#include "../CEX/Dilithium.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Kyber.h"
#include "../CEX/McEliece.h"
#include "../CEX/SphincsPlus.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace Test
{
	using CEX::Tools::IntegerTools;

	const std::string NistPqParser::COUNT_TOKEN("count = ");
	const std::string NistPqParser::SEED_TOKEN("seed = ");
	const std::string NistPqParser::PUBLIC_KEY_TOKEN("pk = ");
	const std::string NistPqParser::PRIVATE_KEY_TOKEN("sk = ");
	const std::string NistPqParser::CIPHERTEXT_TOKEN("ct = ");
	const std::string NistPqParser::SHARED_SECRET_TOKEN("ss = ");
	const std::string NistPqParser::MESSAGE_TOKEN("msg = ");
	const std::string NistPqParser::MESSAGE_LENGTH_TOKEN("mlen = ");
	const std::string NistPqParser::SIGNED_MESSAGE_TOKEN("sm = ");
	const std::string NistPqParser::SIGNED_MESSAGE_LENGTH_TOKEN("smlen = ");

	void NistPqParser::ParseNistCipherKat(const std::string &FilePath,
		std::vector<uint8_t> &Seed, size_t *SeedLength,
		std::vector<uint8_t> &PublicKey, size_t *PublickeyLength,
		std::vector<uint8_t> &PrivateKey, size_t *PrivateKeyLength,
		std::vector<uint8_t> &CipherText, size_t *CipherTextLength,
		std::vector<uint8_t> &SharedSecret, size_t *SharedSecretLength,
		uint32_t SetNumber)
	{
		std::string line;
		std::string tmpl;
		size_t setn;
		size_t slen;

		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				slen = line.size() - COUNT_TOKEN.size();
				tmpl = line.substr(COUNT_TOKEN.size(), slen);
				setn = IntegerTools::FromString<uint32_t>(tmpl, 0, slen);

				if (setn == SetNumber)
				{
					std::getline(ifs, line);

					if (line.find(SEED_TOKEN, 0) != std::string::npos)
					{
						slen = line.size() - SEED_TOKEN.size();
						tmpl = line.substr(SEED_TOKEN.size(), slen);
						slen /= 2;
						*SeedLength = slen;
						Seed.resize(slen);
						HexConverter::Decode(tmpl, Seed);

						std::getline(ifs, line);

						if (line.find(PUBLIC_KEY_TOKEN, 0) != std::string::npos)
						{
							slen = line.size() - PUBLIC_KEY_TOKEN.size();
							tmpl = line.substr(PUBLIC_KEY_TOKEN.size(), slen);
							slen /= 2;
							*PublickeyLength = slen;
							PublicKey.resize(slen);
							HexConverter::Decode(tmpl, PublicKey);

							std::getline(ifs, line);

							if (line.find(PRIVATE_KEY_TOKEN, 0) != std::string::npos)
							{
								slen = line.size() - PRIVATE_KEY_TOKEN.size();
								tmpl = line.substr(PRIVATE_KEY_TOKEN.size(), slen);
								slen /= 2;
								*PrivateKeyLength = slen;
								PrivateKey.resize(slen);
								HexConverter::Decode(tmpl, PrivateKey);

								std::getline(ifs, line);

								if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
								{
									slen = line.size() - CIPHERTEXT_TOKEN.size();
									tmpl = line.substr(CIPHERTEXT_TOKEN.size(), slen);
									slen /= 2;
									*CipherTextLength = slen;
									CipherText.resize(slen);
									HexConverter::Decode(tmpl, CipherText);

									std::getline(ifs, line);

									if (line.find(SHARED_SECRET_TOKEN, 0) != std::string::npos)
									{
										slen = line.size() - SHARED_SECRET_TOKEN.size();
										tmpl = line.substr(SHARED_SECRET_TOKEN.size(), slen);
										slen /= 2;
										*SharedSecretLength = slen;
										SharedSecret.resize(slen);
										HexConverter::Decode(tmpl, SharedSecret);
									}
								}
							}
						}
					}

					break;
				}
			}
		}
	}

	void NistPqParser::ParseNistSignatureKat(const std::string &FilePath,
		std::vector<uint8_t> &Seed, size_t* SeedLength,
		std::vector<uint8_t> &Message, size_t* MessageLength,
		std::vector<uint8_t> &PublicKey, size_t* PublickeyLength,
		std::vector<uint8_t> &PrivateKey, size_t* PrivateKeyLength,
		std::vector<uint8_t> &SignedMessage, size_t* SignedMessageLength,
		uint32_t SetNumber)
	{
		std::string line;
		std::string tmpl;
		size_t setn;
		size_t slen;

		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				slen = line.size() - COUNT_TOKEN.size();
				tmpl = line.substr(COUNT_TOKEN.size(), slen);
				setn = IntegerTools::FromString<uint32_t>(tmpl, 0, slen);

				if (setn == SetNumber)
				{
					std::getline(ifs, line);

					if (line.find(SEED_TOKEN, 0) != std::string::npos)
					{
						slen = line.size() - SEED_TOKEN.size();
						tmpl = line.substr(SEED_TOKEN.size(), slen);
						slen /= 2;
						*SeedLength = slen;
						Seed.resize(slen);
						HexConverter::Decode(tmpl, Seed);

						std::getline(ifs, line);

						if (line.find(MESSAGE_LENGTH_TOKEN, 0) != std::string::npos)
						{
							slen = line.size() - MESSAGE_LENGTH_TOKEN.size();
							tmpl = line.substr(MESSAGE_LENGTH_TOKEN.size(), slen);
							*MessageLength = IntegerTools::FromString<uint32_t>(tmpl, 0, slen);

							std::getline(ifs, line);

							if (line.find(MESSAGE_TOKEN, 0) != std::string::npos)
							{
								slen = line.size() - MESSAGE_TOKEN.size();
								tmpl = line.substr(MESSAGE_TOKEN.size(), slen);
								Message.resize(*MessageLength);
								HexConverter::Decode(tmpl, Message);

								std::getline(ifs, line);

								if (line.find(PUBLIC_KEY_TOKEN, 0) != std::string::npos)
								{
									slen = line.size() - PUBLIC_KEY_TOKEN.size();
									tmpl = line.substr(PUBLIC_KEY_TOKEN.size(), slen);
									slen /= 2;
									*PublickeyLength = slen;
									PublicKey.resize(slen);
									HexConverter::Decode(tmpl, PublicKey);

									std::getline(ifs, line);

									if (line.find(PRIVATE_KEY_TOKEN, 0) != std::string::npos)
									{
										slen = line.size() - PRIVATE_KEY_TOKEN.size();
										tmpl = line.substr(PRIVATE_KEY_TOKEN.size(), slen);
										slen /= 2;
										*PrivateKeyLength = slen;
										PrivateKey.resize(slen);
										HexConverter::Decode(tmpl, PrivateKey);

										std::getline(ifs, line);

										if (line.find(SIGNED_MESSAGE_LENGTH_TOKEN, 0) != std::string::npos)
										{
											slen = line.size() - SIGNED_MESSAGE_LENGTH_TOKEN.size();
											tmpl = line.substr(SIGNED_MESSAGE_LENGTH_TOKEN.size(), slen);
											*SignedMessageLength = IntegerTools::FromString<uint32_t>(tmpl, 0, slen);

											std::getline(ifs, line);

											if (line.find(SIGNED_MESSAGE_TOKEN, 0) != std::string::npos)
											{
												slen = line.size() - SIGNED_MESSAGE_TOKEN.size();
												tmpl = line.substr(SIGNED_MESSAGE_TOKEN.size(), slen);
												SignedMessage.resize(*SignedMessageLength);
												HexConverter::Decode(tmpl, SignedMessage);
											}
										}
									}
								}
							}
						}
					}

					break;
				}
			}
		}
	}
};