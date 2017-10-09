#include "CMACTest.h"
#include "../CEX/CMAC.h"
#include "../CEX/RHX.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Key::Symmetric::SymmetricKey;

	const std::string CMACTest::DESCRIPTION = "CMAC Known Answer Test Vectors for 128/192/256 bit Keys.";
	const std::string CMACTest::FAILURE = "FAILURE! ";
	const std::string CMACTest::SUCCESS = "SUCCESS! All CMAC tests have executed succesfully.";

	CMACTest::CMACTest()
		:
		m_expected(0),
		m_input(0),
		m_keys(0),
		m_progressEvent()
	{
	}

	CMACTest::~CMACTest()
	{
	}

	std::string CMACTest::Run()
	{
		try
		{
			Initialize();

			CompareVector(m_keys[0], m_input[0], m_expected[0]);
			CompareVector(m_keys[0], m_input[1], m_expected[1]);
			CompareVector(m_keys[0], m_input[2], m_expected[2]);
			CompareVector(m_keys[0], m_input[3], m_expected[3]);
			OnProgress(std::string("Passed 128 bit key vector tests.."));
			CompareVector(m_keys[1], m_input[0], m_expected[4]);
			CompareVector(m_keys[1], m_input[1], m_expected[5]);
			CompareVector(m_keys[1], m_input[2], m_expected[6]);
			CompareVector(m_keys[1], m_input[3], m_expected[7]);
			OnProgress(std::string("Passed 192 bit key vector tests.."));
			CompareVector(m_keys[2], m_input[0], m_expected[8]);
			CompareVector(m_keys[2], m_input[1], m_expected[9]);
			CompareVector(m_keys[2], m_input[2], m_expected[10]);
			CompareVector(m_keys[2], m_input[3], m_expected[11]);
			OnProgress(std::string("Passed 256 bit key vector tests.."));
			CompareAccess(m_keys[2]);
			OnProgress(std::string("Passed Finalize/Compute methods output comparison.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(FAILURE + std::string(" : ") + ex.Message());
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + std::string(" : Unknown Error")));
		}
	}

	void CMACTest::CompareAccess(std::vector<byte> &Key)
	{
		Cipher::Symmetric::Block::RHX* eng = new Cipher::Symmetric::Block::RHX();
		Mac::CMAC mac(eng);
		SymmetricKey kp(Key);

		mac.Initialize(kp);
		std::vector<byte> input(64);
		mac.Update(input, 0, input.size());
		std::vector<byte> hash1(16);
		mac.Finalize(hash1, 0);
		std::vector<byte> hash2(16);
		// must reinitialize after a finalizer call
		mac.Initialize(kp);
		mac.Compute(input, hash2);
		delete eng;

		if (hash1 != hash2)
			throw TestException("CMAC is not equal!");
	}

	void CMACTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash(16);
		Cipher::Symmetric::Block::RHX* eng = new Cipher::Symmetric::Block::RHX();
		SymmetricKey kp(Key);

		Mac::CMAC mac(eng);
		mac.Initialize(kp);
		mac.Update(Input, 0, Input.size());
		mac.Finalize(hash, 0);

		delete eng;

		if (Expected != hash)
			throw TestException("CMAC is not equal!");
	}

	void CMACTest::Initialize()
	{
		const char* keysEncoded[3] =
		{
			("2b7e151628aed2a6abf7158809cf4f3c"),
			("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"),
			("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
		};
		HexConverter::Decode(keysEncoded, 3, m_keys);

		const char* inputEncoded[4] =
		{
			(""),
			("6bc1bee22e409f96e93d7e117393172a"),
			("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411"),
			("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
		};
		HexConverter::Decode(inputEncoded, 4, m_input);

		const char* expectedEncoded[12] =
		{
			("bb1d6929e95937287fa37d129b756746"),
			("070a16b46b4d4144f79bdd9dd04a287c"),
			("dfa66747de9ae63030ca32611497c827"),
			("51f0bebf7e3b9d92fc49741779363cfe"),
			("d17ddf46adaacde531cac483de7a9367"),
			("9e99a7bf31e710900662f65e617c5184"),
			("8a1de5be2eb31aad089a82e6ee908b0e"),
			("a1d5df0eed790f794d77589659f39a11"),
			("028962f61b7bf89efc6b551f4667d983"),
			("28a7023f452e8f82bd4bf28d8c37c35c"),
			("aaf3d8f1de5640c232f5b169b9c911e6"),
			("e1992190549f6ed5696a2c056c315410")
		};
		HexConverter::Decode(expectedEncoded, 12, m_expected);
	}

	void CMACTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}