#include "AesAvsTest.h"
#include "TestFiles.h"
#include "../CEX/AHX.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/RHX.h"
#include "../CEX/CBC.h"
#include "../CEX/ECB.h"
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace Test
{
	using namespace Cipher::Block;
	using namespace Cipher::Block::Mode;
	using Cipher::SymmetricKey;
	using Enumeration::BlockCiphers;
	using namespace TestFiles::AESAVS;
	const std::string AesAvsTest::CLASSNAME = "AesAvsTest";
	const std::string AesAvsTest::DESCRIPTION = "NIST Advanced Encryption Standard Algorithm Validation Suite (AESAVS) tests.";
	const std::string AesAvsTest::SUCCESS = "SUCCESS! AESAVS tests have executed succesfully.";
	const std::string AesAvsTest::COUNT_TOKEN = "COUNT = ";
	const std::string AesAvsTest::IV_TOKEN = "IV = ";
	const std::string AesAvsTest::KEY_TOKEN = "KEY = ";
	const std::string AesAvsTest::PLAINTEXT_TOKEN = "PLAINTEXT = ";
	const std::string AesAvsTest::CIPHERTEXT_TOKEN = "CIPHERTEXT = ";
	const bool AesAvsTest::HAS_AESNI = HasAESNI();

	//~~~Constructor~~~//

	AesAvsTest::AesAvsTest(bool TestAesNi)
		:
		m_progressEvent(),
		m_aesniTest(TestAesNi && HAS_AESNI)
	{
	}

	AesAvsTest::~AesAvsTest()
	{
		m_aesniTest = false;
	}

	//~~~Accessors~~~//

	const std::string AesAvsTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &AesAvsTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string AesAvsTest::Run()
	{
		try
		{
			RHX* cprr = new RHX();

			// AESAVS varrkey and vartxt KAT tests
			CbcKat(cprr, AESCBC128_VARKEY);
			CbcKat(cprr, AESCBC256_VARKEY);
			OnProgress(std::string("AESAVSTest: Passed standard CBC AES-128/256 AESAVS KAT key tests.."));

			CbcKat(cprr, AESCBC128_VARTXT);
			CbcKat(cprr, AESCBC256_VARTXT);
			OnProgress(std::string("AESAVSTest: Passed standard CBC AES-128/256 AESAVS KAT text tests.."));

			EbcKat(cprr, AESECB128_VARKEY);
			EbcKat(cprr, AESECB256_VARKEY);
			OnProgress(std::string("AESAVSTest: Passed standard ECB AES-128/256 AESAVS KAT key tests.."));

			EbcKat(cprr, AESECB128_VARTXT);
			EbcKat(cprr, AESECB256_VARTXT);
			OnProgress(std::string("AESAVSTest: Passed standard ECB AES-128/256 AESAVS KAT text tests.."));

			// AESAVS monte carlo tests
			CbcMct(cprr, AESCBC128_MCT);
			CbcMct(cprr, AESCBC256_MCT);
			OnProgress(std::string("AESAVSTest: Passed standard CBC AES-128/256 AESAVS Monte Carlo tests.."));

			EcbMct(cprr, AESECB128_MCT);
			EcbMct(cprr, AESECB256_MCT);
			OnProgress(std::string("AESAVSTest: Passed standard ECB AES-128/256 AESAVS Monte Carlo tests.."));

			CbcMmt(cprr, AESCBC128_MMT);
			CbcMmt(cprr, AESCBC256_MMT);
			OnProgress(std::string("AESAVSTest: Passed standard CBC AES-128/256 AESAVS Multi-block Message tests.."));

			EcbMmt(cprr, AESECB128_MMT);
			EcbMmt(cprr, AESECB256_MMT);
			OnProgress(std::string("AESAVSTest: Passed standard ECB AES-128/256 AESAVS Multi-block Message tests.."));

			if (HAS_AESNI)
			{
				AHX* cpra = new AHX();

				// AESAVS varrkey and vartxt KAT tests
				CbcKat(cpra, AESCBC128_VARKEY);
				CbcKat(cpra, AESCBC256_VARKEY);
				OnProgress(std::string("AESAVSTest: Passed AES-NI CBC AES-128/256 AESAVS KAT key tests.."));

				CbcKat(cpra, AESCBC128_VARTXT);
				CbcKat(cpra, AESCBC256_VARTXT);
				OnProgress(std::string("AESAVSTest: Passed AES-NI CBC AES-128/256 AESAVS KAT text tests.."));

				EbcKat(cpra, AESECB128_VARKEY);
				EbcKat(cpra, AESECB256_VARKEY);
				OnProgress(std::string("AESAVSTest: Passed AES-NI ECB AES-128/256 AESAVS KAT key tests.."));

				EbcKat(cpra, AESECB128_VARTXT);
				EbcKat(cpra, AESECB256_VARTXT);
				OnProgress(std::string("AESAVSTest: Passed AES-NI ECB AES-128/256 AESAVS KAT text tests.."));

				// AESAVS monte carlo tests
				CbcMct(cpra, AESCBC128_MCT);
				CbcMct(cpra, AESCBC256_MCT);
				OnProgress(std::string("AESAVSTest: Passed AES-NI CBC AES-128/256 AESAVS Monte Carlo tests.."));

				EcbMct(cpra, AESECB128_MCT);
				EcbMct(cpra, AESECB256_MCT);
				OnProgress(std::string("AESAVSTest: Passed AES-NI ECB AES-128/256 AESAVS Monte Carlo tests.."));

				CbcMmt(cpra, AESCBC128_MMT);
				CbcMmt(cpra, AESCBC256_MMT);
				OnProgress(std::string("AESAVSTest: Passed standard CBC AES-128/256 AESAVS Multi-block Message tests.."));

				EcbMmt(cpra, AESECB128_MMT);
				EcbMmt(cpra, AESECB256_MMT);
				OnProgress(std::string("AESAVSTest: Passed standard ECB AES-128/256 AESAVS Multi-block Message tests.."));
			}

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	//~~~Private Functions~~~//

	void AesAvsTest::CbcKat(IBlockCipher* Cipher, const std::string &FilePath)
	{
		std::string line;
		std::string tmpl;
		std::vector<byte> dec;
		std::vector<byte> enc;
		std::vector<byte> exp;
		std::vector<byte> iv;
		std::vector<byte> ivc;
		std::vector<byte> key;
		std::vector<byte> pln;
		size_t i;

		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				for (i = 0; i < 4; ++i)
				{
					std::getline(ifs, line);

					if (line.find(KEY_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(KEY_TOKEN.size(), line.size() - KEY_TOKEN.size());
						HexConverter::Decode(tmpl, key);
					}
					else if (line.find(PLAINTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(PLAINTEXT_TOKEN.size(), line.size() - PLAINTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, pln);
						dec.resize(pln.size());
					}
					else if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(CIPHERTEXT_TOKEN.size(), line.size() - CIPHERTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, exp);
						enc.resize(exp.size());
					}
					else if (line.find(IV_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(IV_TOKEN.size(), line.size() - IV_TOKEN.size());
						HexConverter::Decode(tmpl, iv);
						ivc.resize(iv.size());
					}
				}

				std::memcpy(ivc.data(), iv.data(), ivc.size());
				CBC cpr(Cipher);
				SymmetricKey kp1(key, iv);
				cpr.Initialize(true, kp1);
				cpr.EncryptBlock(pln, enc);

				if (enc != exp)
				{
					throw TestException(std::string("Kat"), std::string("CBC(AES)"), std::string("Encrypted output does not match the input! -AK1"));
				}

				SymmetricKey kp2(key, ivc);
				cpr.Initialize(false, kp2);
				cpr.DecryptBlock(enc, dec);

				if (dec != pln)
				{
					throw TestException(std::string("Kat"), std::string("CBC(AES)"), std::string("Decrypted output does not match the input! -AK2"));
				}
			}
		}
	}

	void AesAvsTest::EbcKat(IBlockCipher* Cipher, const std::string &FilePath)
	{
		std::string line;
		std::string tmpl;
		std::vector<byte> dec;
		std::vector<byte> enc;
		std::vector<byte> exp;
		std::vector<byte> key;
		std::vector<byte> pln;
		size_t i;

		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				for (i = 0; i < 4; ++i)
				{
					std::getline(ifs, line);

					if (line.find(KEY_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(KEY_TOKEN.size(), line.size() - KEY_TOKEN.size());
						HexConverter::Decode(tmpl, key);
					}
					else if (line.find(PLAINTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(PLAINTEXT_TOKEN.size(), line.size() - PLAINTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, pln);
						dec.resize(pln.size());
					}
					else if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(CIPHERTEXT_TOKEN.size(), line.size() - CIPHERTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, exp);
						enc.resize(exp.size());
					}
				}

				ECB cpr(Cipher);
				SymmetricKey kp(key);
				cpr.Initialize(true, kp);
				cpr.EncryptBlock(pln, enc);

				if (enc != exp)
				{
					throw TestException(std::string("Kat"), std::string("ECB(AES)"), std::string("Encrypted output does not match the input! -AK3"));
				}

				cpr.Initialize(false, kp);
				cpr.DecryptBlock(enc, dec);

				if (dec != pln)
				{
					throw TestException(std::string("Kat"), std::string("ECB(AES)"), std::string("Decrypted output does not match the input! -AK4"));
				}
			}
		}
	}

	void AesAvsTest::CbcMct(IBlockCipher* Cipher, const std::string &FilePath)
	{
		std::string line;
		std::string tmpl;
		std::vector<byte> dec;
		std::vector<byte> decc;
		std::vector<byte> enc;
		std::vector<byte> encc;
		std::vector<byte> exp;
		std::vector<byte> iv;
		std::vector<byte> ivc;
		std::vector<byte> key;
		std::vector<byte> pln;
		std::vector<byte> plnc;
		size_t count;
		size_t i;

		count = 0;
		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				++count;

				for (i = 0; i < 4; ++i)
				{
					std::getline(ifs, line);

					if (line.find(KEY_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(KEY_TOKEN.size(), line.size() - KEY_TOKEN.size());
						HexConverter::Decode(tmpl, key);
					}
					else if (line.find(PLAINTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(PLAINTEXT_TOKEN.size(), line.size() - PLAINTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, pln);
						plnc.resize(pln.size());
						dec.resize(pln.size());
						decc.resize(pln.size());
					}
					else if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(CIPHERTEXT_TOKEN.size(), line.size() - CIPHERTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, exp);
						enc.resize(exp.size());
						encc.resize(exp.size());
					}
					else if (line.find(IV_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(IV_TOKEN.size(), line.size() - IV_TOKEN.size());
						HexConverter::Decode(tmpl, iv);
						ivc.resize(iv.size());
					}
				}

				std::memcpy(ivc.data(), iv.data(), ivc.size());
				std::memcpy(plnc.data(), pln.data(), plnc.size());

				if (count <= 100)
				{
					CBC cpr(Cipher);
					SymmetricKey kp(key, ivc);
					cpr.Initialize(true, kp);

					for (i = 0; i < 1000; ++i)
					{
						if (i != 0)
						{
							std::memcpy(encc.data(), enc.data(), encc.size());
							cpr.EncryptBlock(plnc, enc);
							std::memcpy(plnc.data(), encc.data(), plnc.size());
						}
						else
						{
							cpr.EncryptBlock(plnc, enc);
							std::memcpy(plnc.data(), iv.data(), plnc.size());
						}
					}

					if (enc != exp)
					{
						throw TestException(std::string("Monte Carlo"), std::string("CBC(AES)"), std::string("Encrypted output does not match the input! -AM1"));
					}
				}
				else
				{
					std::memcpy(enc.data(), exp.data(), enc.size());

					CBC cpr(Cipher);
					SymmetricKey kp(key, ivc);
					cpr.Initialize(false, kp);

					for (i = 0; i < 1000; ++i)
					{
						if (i != 0)
						{
							std::memcpy(decc.data(), dec.data(), decc.size());
							cpr.DecryptBlock(enc, dec);
							std::memcpy(enc.data(), decc.data(), enc.size());
						}
						else
						{
							cpr.DecryptBlock(enc, dec);
							std::memcpy(enc.data(), iv.data(), enc.size());
						}
					}

					if (dec != pln)
					{
						throw TestException(std::string("Monte Carlo"), std::string("CBC(AES)"), std::string("Decrypted output does not match the input! -AM2"));
					}
				}
			}
		}
	}

	void AesAvsTest::EcbMct(IBlockCipher* Cipher, const std::string &FilePath)
	{
		std::string line;
		std::string tmpl;
		std::vector<byte> dec;
		std::vector<byte> enc;
		std::vector<byte> exp;
		std::vector<byte> key;
		std::vector<byte> pln;
		std::vector<byte> plnc;
		size_t i;

		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				for (i = 0; i < 3; ++i)
				{
					std::getline(ifs, line);

					if (line.find(KEY_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(KEY_TOKEN.size(), line.size() - KEY_TOKEN.size());
						HexConverter::Decode(tmpl, key);
					}
					else if (line.find(PLAINTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(PLAINTEXT_TOKEN.size(), line.size() - PLAINTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, pln);
						plnc.resize(pln.size());
						dec.resize(pln.size());
					}
					else if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(CIPHERTEXT_TOKEN.size(), line.size() - CIPHERTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, exp);
						enc.resize(exp.size());
					}
				}

				std::memcpy(plnc.data(), pln.data(), plnc.size());

				ECB cpr(Cipher);
				SymmetricKey kp(key);
				cpr.Initialize(true, kp);
				
				for (i = 0; i < 1000; ++i)
				{
					cpr.EncryptBlock(plnc, enc);
					std::memcpy(plnc.data(), enc.data(), plnc.size());
				}

				if (enc != exp)
				{
					throw TestException(std::string("Monte Carlo"), std::string("ECB(AES)"), std::string("Encrypted output does not match the input! -AM3"));
				}

				cpr.Initialize(false, kp);

				for (i = 0; i < 1000; ++i)
				{
					cpr.DecryptBlock(enc, dec);
					std::memcpy(enc.data(), dec.data(), enc.size());
				}

				if (dec != pln)
				{
					throw TestException(std::string("Monte Carlo"), std::string("ECB(AES)"), std::string("Decrypted output does not match the input! -AM4"));
				}
			}
		}
	}

	void AesAvsTest::CbcMmt(IBlockCipher* Cipher, const std::string &FilePath)
	{
		const size_t BLOCK_SIZE = 16;
		std::string line;
		std::string tmpl;
		std::vector<byte> dec;
		std::vector<byte> enc;
		std::vector<byte> exp;
		std::vector<byte> iv;
		std::vector<byte> key;
		std::vector<byte> pln;
		size_t count;
		size_t i;

		count = 0;
		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				++count;

				for (i = 0; i < 4; ++i)
				{
					std::getline(ifs, line);

					if (line.find(KEY_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(KEY_TOKEN.size(), line.size() - KEY_TOKEN.size());
						HexConverter::Decode(tmpl, key);
					}
					else if (line.find(PLAINTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(PLAINTEXT_TOKEN.size(), line.size() - PLAINTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, pln);
						dec.resize(pln.size());
					}
					else if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(CIPHERTEXT_TOKEN.size(), line.size() - CIPHERTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, exp);
						enc.resize(exp.size());
					}
					else if (line.find(IV_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(IV_TOKEN.size(), line.size() - IV_TOKEN.size());
						HexConverter::Decode(tmpl, iv);
					}
				}

				if (count <= 10)
				{
					CBC cpr(Cipher);
					SymmetricKey kp(key, iv);
					cpr.Initialize(true, kp);

					for (i = 0; i < pln.size() / BLOCK_SIZE; ++i)
					{
						cpr.EncryptBlock(pln, i * BLOCK_SIZE, enc, i * BLOCK_SIZE);
					}

					if (enc != exp)
					{
						throw TestException(std::string("Multi Block"), std::string("CBC(AES)"), std::string("Encrypted output does not match the input! -AB1"));
					}
				}
				else
				{
					CBC cpr(Cipher);
					SymmetricKey kp(key, iv);
					cpr.Initialize(false, kp);

					for (i = 0; i < exp.size() / BLOCK_SIZE; ++i)
					{
						cpr.DecryptBlock(exp, i * BLOCK_SIZE, dec, i * BLOCK_SIZE);
					}

					if (dec != pln)
					{
						throw TestException(std::string("Multi Block"), std::string("CBC(AES)"), std::string("Decrypted output does not match the input! -AB2"));
					}
				}
			}
		}
	}

	void AesAvsTest::EcbMmt(IBlockCipher* Cipher, const std::string &FilePath)
	{
		const size_t BLOCK_SIZE = 16;
		std::string line;
		std::string tmpl;
		std::vector<byte> dec;
		std::vector<byte> enc;
		std::vector<byte> exp;
		std::vector<byte> key;
		std::vector<byte> pln;
		size_t count;
		size_t i;

		count = 0;
		std::ifstream ifs(FilePath);

		if (!ifs || !ifs.is_open())
		{
			throw TestException(std::string("Read"), FilePath, std::string("Could not open the file!"));
		}

		while (std::getline(ifs, line))
		{
			if (line.find(COUNT_TOKEN, 0) != std::string::npos)
			{
				++count;

				for (i = 0; i < 3; ++i)
				{
					std::getline(ifs, line);

					if (line.find(KEY_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(KEY_TOKEN.size(), line.size() - KEY_TOKEN.size());
						HexConverter::Decode(tmpl, key);
					}
					else if (line.find(PLAINTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(PLAINTEXT_TOKEN.size(), line.size() - PLAINTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, pln);
						dec.resize(pln.size());
					}
					else if (line.find(CIPHERTEXT_TOKEN, 0) != std::string::npos)
					{
						tmpl = line.substr(CIPHERTEXT_TOKEN.size(), line.size() - CIPHERTEXT_TOKEN.size());
						HexConverter::Decode(tmpl, exp);
						enc.resize(exp.size());
					}
				}

				if (count <= 10)
				{
					ECB cpr(Cipher);
					SymmetricKey kp(key);
					cpr.Initialize(true, kp);

					for (i = 0; i < pln.size() / BLOCK_SIZE; ++i)
					{
						cpr.EncryptBlock(pln, i * BLOCK_SIZE, enc, i * BLOCK_SIZE);
					}

					if (enc != exp)
					{
						throw TestException(std::string("Multi Block"), std::string("ECB(AES)"), std::string("Encrypted output does not match the input! -AB3"));
					}
				}
				else
				{
					ECB cpr(Cipher);
					SymmetricKey kp(key);
					cpr.Initialize(false, kp);

					for (i = 0; i < exp.size() / BLOCK_SIZE; ++i)
					{
						cpr.DecryptBlock(exp, i * BLOCK_SIZE, dec, i * BLOCK_SIZE);
					}

					if (dec != pln)
					{
						throw TestException(std::string("Multi Block"), std::string("CBC(AES)"), std::string("Decrypted output does not match the input! -AB4"));
					}
				}
			}
		}
	}

	bool AesAvsTest::HasAESNI()
	{
#if defined(__AVX__)
		CpuDetect dtc;

		return dtc.AVX() && dtc.AESNI();
#else
		return false;
#endif
	}

	void AesAvsTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
