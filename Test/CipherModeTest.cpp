#include "CipherModeTest.h"
#include "../CEX/CBC.h"
#include "../CEX/CFB.h"
#include "../CEX/CTR.h"
#include "../CEX/ECB.h"
#include "../CEX/OFB.h"
#include "../CEX/RHX.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string CipherModeTest::DESCRIPTION = "NIST SP800-38A KATs testing CBC, CFB, CTR, ECB, and OFB modes.";
	const std::string CipherModeTest::FAILURE = "FAILURE! ";
	const std::string CipherModeTest::SUCCESS = "SUCCESS! Cipher Mode tests have executed succesfully.";

	CipherModeTest::CipherModeTest()
		:
		m_input(0),
		m_keys(0),
		m_output(0),
		m_progressEvent(),
		m_vectors(0)
	{
	}

	CipherModeTest::~CipherModeTest()
	{
	}

	std::string CipherModeTest::Run()
	{
		try
		{
			Initialize();

			// test modes with each key (128/192/256)
			CompareCBC(m_keys[0], m_input, m_output);
			CompareCBC(m_keys[1], m_input, m_output);
			CompareCBC(m_keys[2], m_input, m_output);
			OnProgress(std::string("CipherModeTest: Passed CBC 128/192/256 bit key encryption/decryption tests.."));

			CompareCFB(m_keys[0], m_input, m_output);
			CompareCFB(m_keys[1], m_input, m_output);
			CompareCFB(m_keys[2], m_input, m_output);
			OnProgress(std::string("CipherModeTest: Passed CFB 128/192/256 bit key encryption/decryption tests.."));

			CompareCTR(m_keys[0], m_input, m_output);
			CompareCTR(m_keys[1], m_input, m_output);
			CompareCTR(m_keys[2], m_input, m_output);
			OnProgress(std::string("CipherModeTest: Passed CTR 128/192/256 bit key encryption/decryption tests.."));

			CompareECB(m_keys[0], m_input, m_output);
			CompareECB(m_keys[1], m_input, m_output);
			CompareECB(m_keys[2], m_input, m_output);
			OnProgress(std::string("CipherModeTest: Passed ECB 128/192/256 bit key encryption/decryption tests.."));

			CompareOFB(m_keys[0], m_input, m_output);
			CompareOFB(m_keys[1], m_input, m_output);
			CompareOFB(m_keys[2], m_input, m_output);
			OnProgress(std::string("CipherModeTest: Passed OFB 128/192/256 bit key encryption/decryption tests.."));

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Unknown Error"));
		}
	}

	void CipherModeTest::CompareCBC(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output)
	{
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> &iv = m_vectors[0];
		int index = 6;

		if (Key.size() == 24)
			index = 8;
		else if (Key.size() == 32)
			index = 10;

		{
			RHX* eng = new RHX();
			Mode::CBC mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(true, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != Output[index][i])
					throw TestException("CBC Mode: Encrypted arrays are not equal!");
			}
			delete eng;
		}

		index++;
		{
			RHX* eng = new RHX();
			Mode::CBC mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(false, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != m_output[index][i])
					throw TestException("CBC Mode: Decrypted arrays are not equal!");
			}
			delete eng;
		}
	}

	void CipherModeTest::CompareCFB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output)
	{
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> &iv = m_vectors[0];
		int index = 12;

		if (Key.size() == 24)
			index = 14;
		else if (Key.size() == 32)
			index = 16;

		{
			RHX* eng = new RHX();
			Mode::CFB mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(true, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], 0, outBytes, 0);

				if (outBytes != Output[index][i])
					throw TestException("CFB Mode: Encrypted arrays are not equal!");
			}
			delete eng;
		}

		index++;

		{
			RHX* eng = new RHX();
			Mode::CFB mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(false, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != m_output[index][i])
					throw TestException("CFB Mode: Decrypted arrays are not equal!");
			}
			delete eng;
		}
	}

	void CipherModeTest::CompareCTR(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output)
	{
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> &iv = m_vectors[1];
		int index = 24;

		if (Key.size() == 24)
			index = 26;
		else if (Key.size() == 32)
			index = 28;

		{
			RHX* eng = new RHX();
			Mode::CTR mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(true, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != Output[index][i])
					throw TestException("CTR Mode: Encrypted arrays are not equal!");
			}
			delete eng;
		}

		index++;
		{
			RHX* eng = new RHX();
			Mode::CTR mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(false, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != m_output[index][i])
					throw TestException("CTR Mode: Decrypted arrays are not equal!");
			}
			delete eng;
		}
	}

	void CipherModeTest::CompareECB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output)
	{
		std::vector<byte> outBytes(16, 0);
		int index = 0;

		if (Key.size() == 24)
			index = 2;
		else if (Key.size() == 32)
			index = 4;

		{
			RHX* eng = new RHX();
			Mode::ECB mode(eng);
			Key::Symmetric::SymmetricKey k(Key);
			mode.Initialize(true, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != Output[index][i])
					throw TestException("ECB Mode: Encrypted arrays are not equal!");
			}
			delete eng;
		}

		index++;

		{
			RHX* eng = new RHX();
			Mode::ECB mode(eng);
			Key::Symmetric::SymmetricKey k(Key);
			mode.Initialize(false, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != m_output[index][i])
					throw TestException("ECB Mode: Decrypted arrays are not equal!");
			}
			delete eng;
		}
	}

	void CipherModeTest::CompareOFB(std::vector<byte> &Key, std::vector<std::vector<std::vector<byte>>> &Input, std::vector<std::vector<std::vector<byte>>> &Output)
	{
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> &iv = m_vectors[0];
		int index = 18;

		if (Key.size() == 24)
			index = 20;
		else if (Key.size() == 32)
			index = 22;

		{
			RHX* eng = new RHX();
			Mode::OFB mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(true, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != Output[index][i])
					throw TestException("OFB Mode: Encrypted arrays are not equal!");
			}
			delete eng;
		}

		index++;

		{
			RHX* eng = new RHX();
			Mode::OFB mode(eng);
			Key::Symmetric::SymmetricKey k(Key, iv);
			mode.Initialize(true, k);

			for (unsigned int i = 0; i < 4; i++)
			{
				mode.Transform(Input[index][i], outBytes);

				if (outBytes != m_output[index][i])
					throw TestException("OFB Mode: Decrypted arrays are not equal!");
			}
			delete eng;
		}
	}

	void CipherModeTest::Initialize()
	{
		const char* keysEncoded[3] =
		{
			("2b7e151628aed2a6abf7158809cf4f3c"),//F.1/F.2/F.3/F.5 -128
			("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),//F.1/F.2/F.3/F.5 -192
			("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"),//F.1/F.2/F.3/F.5 -256
		};
		HexConverter::Decode(keysEncoded, 3, m_keys);

		const char* vectorsEncoded[2] =
		{
			("000102030405060708090a0b0c0d0e0f"),//F.1/F.2/F.3
			("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")//F.5
		};
		HexConverter::Decode(vectorsEncoded, 2, m_vectors);

		const char* inputEncoded[][4] =
		{
			{
			//ecb input
			("6bc1bee22e409f96e93d7e117393172a"),//F.1.1 ECB-AES128.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("3ad77bb40d7a3660a89ecaf32466ef97"),//F.1.2 ECB-AES128.Decrypt
			("f5d3d58503b9699de785895a96fdbaaf"),
			("43b1cd7f598ece23881b00e3ed030688"),
			("7b0c785e27e8ad3f8223207104725dd4")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.1.3 ECB-AES192.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("bd334f1d6e45f25ff712a214571fa5cc"),//F.1.4 ECB-AES192.Decrypt
			("974104846d0ad3ad7734ecb3ecee4eef"),
			("ef7afd2270e2e60adce0ba2face6444e"),
			("9a4b41ba738d6c72fb16691603c18e0e")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.1.5 ECB-AES256.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("f3eed1bdb5d2a03c064b5a7e3db181f8"),//F.1.6 ECB-AES256.Decrypt
			("591ccb10d410ed26dc5ba74a31362870"),
			("b6ed21b99ca6f4f9f153e7b1beafed1d"),
			("23304b7a39f9f3ff067d8d8f9e24ecc7")
			},
			//cbc input
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.2.1 CBC-AES128.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("7649abac8119b246cee98e9b12e9197d"),//F.2.2 CBC-AES128.Decrypt
			("5086cb9b507219ee95db113a917678b2"),
			("73bed6b8e3c1743b7116e69e22229516"),
			("3ff1caa1681fac09120eca307586e1a7")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.2.3 CBC-AES192.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("4f021db243bc633d7178183a9fa071e8"),//F.2.4 CBC-AES192.Decrypt
			("b4d9ada9ad7dedf4e5e738763f69145a"),
			("571b242012fb7ae07fa9baac3df102e0"),
			("08b0e27988598881d920a9e64f5615cd")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.2.5 CBC-AES256.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),//F.2.6 CBC-AES256.Decrypt
			("9cfc4e967edb808d679f777bc6702c7d"),
			("39f23369a9d9bacfa530e26304231461"),
			("b2eb05e2c39be9fcda6c19078c6a9d1b")
			},
			// cfb input
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.3.13 CFB128-AES128.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("3b3fd92eb72dad20333449f8e83cfb4a"),//F.3.14 CFB128-AES128.Decrypt
			("c8a64537a0b3a93fcde3cdad9f1ce58b"),
			("26751f67a3cbb140b1808cf187a4f4df"),
			("c04b05357c5d1c0eeac4c66f9ff7f2e6")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.3.15 CFB128-AES192.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("cdc80d6fddf18cab34c25909c99a4174"),//F.3.16 CFB128-AES192.Decrypt
			("67ce7f7f81173621961a2b70171d3d7a"),
			("2e1e8a1dd59b88b1c8e60fed1efac4c9"),
			("c05f9f9ca9834fa042ae8fba584b09ff")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.3.17 CFB128-AES256.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("dc7e84bfda79164b7ecd8486985d3860"),//F.3.18 CFB128-AES256.Decrypt
			("39ffed143b28b1c832113c6331e5407b"),
			("df10132415e54b92a13ed0a8267ae2f9"),
			("75a385741ab9cef82031623d55b1e471")
			},
			// ofb input
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.4.1 OFB-AES128.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710"),
			},
			{
			("3b3fd92eb72dad20333449f8e83cfb4a"),//F.4.2 OFB-AES128.Decrypt
			("7789508d16918f03f53c52dac54ed825"),
			("9740051e9c5fecf64344f7a82260edcc"),
			("304c6528f659c77866a510d9c1d6ae5e")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.4.3 OFB-AES192.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("cdc80d6fddf18cab34c25909c99a4174"),//F.4.4 OFB-AES192.Decrypt
			("fcc28b8d4c63837c09e81700c1100401"),
			("8d9a9aeac0f6596f559c6d4daf59a5f2"),
			("6d9f200857ca6c3e9cac524bd9acc92a")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.4.5 OFB-AES256.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("dc7e84bfda79164b7ecd8486985d3860"),//F.4.6 OFB-AES256.Decrypt
			("4febdc6740d20b3ac88f6ad82a4fb08d"),
			("71ab47a086e86eedf39d1c5bba97c408"),
			("0126141d67f37be8538f5a8be740e484")
			},
			{
			//ctr input
			("6bc1bee22e409f96e93d7e117393172a"),//F.5.1 CTR-AES128.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("874d6191b620e3261bef6864990db6ce"),//F.5.2 CTR-AES128.Decrypt
			("9806f66b7970fdff8617187bb9fffdff"),
			("5ae4df3edbd5d35e5b4f09020db03eab"),
			("1e031dda2fbe03d1792170a0f3009cee")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.5.3 CTR-AES192.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("1abc932417521ca24f2b0459fe7e6e0b"),//F.5.4 CTR-AES192.Decrypt
			("090339ec0aa6faefd5ccc2c6f4ce8e94"),
			("1e36b26bd1ebc670d1bd1d665620abf7"),
			("4f78a7f6d29809585a97daec58c6b050")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.5.5 CTR-AES256.Encrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("601ec313775789a5b7a7f504bbf3d228"),//F.5.6 CTR-AES256.Decrypt
			("f443e3ca4d62b59aca84e990cacaf5c5"),
			("2b0930daa23de94ce87017ba2d84988d"),
			("dfc9c58db67aada613c2dd08457941a6")
			}
		};

		size_t inputSize = sizeof(inputEncoded) / sizeof(inputEncoded[0]);
		m_input.resize(inputSize);

		for (unsigned int i = 0; i < inputSize; ++i)
			HexConverter::Decode(inputEncoded[i], 4, m_input[i]);

		const char *outputEncoded[][4] =
		{
			//ecb output
			{
			("3ad77bb40d7a3660a89ecaf32466ef97"),//F.1.1 ECB-AES128.Encrypt
			("f5d3d58503b9699de785895a96fdbaaf"),
			("43b1cd7f598ece23881b00e3ed030688"),
			("7b0c785e27e8ad3f8223207104725dd4")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.1.2 ECB-AES128.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("bd334f1d6e45f25ff712a214571fa5cc"),//F.1.3 ECB-AES192.Encrypt
			("974104846d0ad3ad7734ecb3ecee4eef"),
			("ef7afd2270e2e60adce0ba2face6444e"),
			("9a4b41ba738d6c72fb16691603c18e0e")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.1.4 ECB-AES192.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("f3eed1bdb5d2a03c064b5a7e3db181f8"),//F.1.5 ECB-AES256.Encrypt
			("591ccb10d410ed26dc5ba74a31362870"),
			("b6ed21b99ca6f4f9f153e7b1beafed1d"),
			("23304b7a39f9f3ff067d8d8f9e24ecc7")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.1.6 ECB-AES256.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			//cbc output
			{
			("7649abac8119b246cee98e9b12e9197d"),//F.2.1 CBC-AES128.Encrypt
			("5086cb9b507219ee95db113a917678b2"),
			("73bed6b8e3c1743b7116e69e22229516"),
			("3ff1caa1681fac09120eca307586e1a7"),
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.2.2 CBC-AES128.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("4f021db243bc633d7178183a9fa071e8"),//F.2.3 CBC-AES192.Encrypt
			("b4d9ada9ad7dedf4e5e738763f69145a"),
			("571b242012fb7ae07fa9baac3df102e0"),
			("08b0e27988598881d920a9e64f5615cd")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.2.4 CBC-AES192.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("f58c4c04d6e5f1ba779eabfb5f7bfbd6"),//F.2.5 CBC-AES256.Encrypt
			("9cfc4e967edb808d679f777bc6702c7d"),
			("39f23369a9d9bacfa530e26304231461"),
			("b2eb05e2c39be9fcda6c19078c6a9d1b")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.2.6 CBC-AES256.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			// cfb output
			{
			("3b3fd92eb72dad20333449f8e83cfb4a"),//F.3.13 CFB128-AES128.Encrypt
			("c8a64537a0b3a93fcde3cdad9f1ce58b"),
			("26751f67a3cbb140b1808cf187a4f4df"),
			("c04b05357c5d1c0eeac4c66f9ff7f2e6")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.3.14 CFB128-AES128.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("cdc80d6fddf18cab34c25909c99a4174"),//F.3.15 CFB128-AES192.Encrypt
			("67ce7f7f81173621961a2b70171d3d7a"),
			("2e1e8a1dd59b88b1c8e60fed1efac4c9"),
			("c05f9f9ca9834fa042ae8fba584b09ff")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.3.16 CFB128-AES192.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("dc7e84bfda79164b7ecd8486985d3860"),//F.3.17 CFB128-AES256.Encrypt
			("39ffed143b28b1c832113c6331e5407b"),
			("df10132415e54b92a13ed0a8267ae2f9"),
			("75a385741ab9cef82031623d55b1e471")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.3.6  CFB128-AES256.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			// ofb output
			{
			("3b3fd92eb72dad20333449f8e83cfb4a"),//F.4.1 OFB-AES128.Encrypt
			("7789508d16918f03f53c52dac54ed825"),
			("9740051e9c5fecf64344f7a82260edcc"),
			("304c6528f659c77866a510d9c1d6ae5e"),
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.4.2 OFB-AES128.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("cdc80d6fddf18cab34c25909c99a4174"),//F.4.3 OFB-AES192.Encrypt
			("fcc28b8d4c63837c09e81700c1100401"),
			("8d9a9aeac0f6596f559c6d4daf59a5f2"),
			("6d9f200857ca6c3e9cac524bd9acc92a")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.4.4 OFB-AES192.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("dc7e84bfda79164b7ecd8486985d3860"),//F.4.5 OFB-AES256.Encrypt
			("4febdc6740d20b3ac88f6ad82a4fb08d"),
			("71ab47a086e86eedf39d1c5bba97c408"),
			("0126141d67f37be8538f5a8be740e484")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.4.6 OFB-AES256.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			//ctr output
			{
			("874d6191b620e3261bef6864990db6ce"),//F.5.1 CTR-AES128.Encrypt
			("9806f66b7970fdff8617187bb9fffdff"),
			("5ae4df3edbd5d35e5b4f09020db03eab"),
			("1e031dda2fbe03d1792170a0f3009cee")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.5.2 CTR-AES128.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("1abc932417521ca24f2b0459fe7e6e0b"),//F.5.3 CTR-AES192.Encrypt
			("090339ec0aa6faefd5ccc2c6f4ce8e94"),
			("1e36b26bd1ebc670d1bd1d665620abf7"),
			("4f78a7f6d29809585a97daec58c6b050")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.5.4 CTR-AES192.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			},
			{
			("601ec313775789a5b7a7f504bbf3d228"),//F.5.5 CTR-AES256.Encrypt
			("f443e3ca4d62b59aca84e990cacaf5c5"),
			("2b0930daa23de94ce87017ba2d84988d"),
			("dfc9c58db67aada613c2dd08457941a6")
			},
			{
			("6bc1bee22e409f96e93d7e117393172a"),//F.5.6 CTR-AES256.Decrypt
			("ae2d8a571e03ac9c9eb76fac45af8e51"),
			("30c81c46a35ce411e5fbc1191a0a52ef"),
			("f69f2445df4f9b17ad2b417be66c3710")
			}
		};

		size_t outputSize = sizeof(outputEncoded) / sizeof(outputEncoded[0]);
		m_output.resize(outputSize);

		for (unsigned int i = 0; i < outputSize; ++i)
			HexConverter::Decode(outputEncoded[i], 4, m_output[i]);
	}

	void CipherModeTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}