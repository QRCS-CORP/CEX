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
		m_progressEvent()
	{
		Initialize();
	}

	CMACTest::~CMACTest()
	{
	}

	const std::string CMACTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CMACTest::Progress()
	{
		return m_progressEvent;
	}

	std::string CMACTest::Run()
	{
		try
		{
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
		{
			throw TestException("CMAC is not equal!");
		}
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
		{
			throw TestException("CMAC is not equal!");
		}
	}

	void CMACTest::Initialize()
	{
		const std::vector<std::string> keys =
		{
			std::string("2B7E151628AED2A6ABF7158809CF4F3C"),
			std::string("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B"),
			std::string("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4")
		};
		HexConverter::Decode(keys, 3, m_keys);

		const std::vector<std::string> input =
		{
			std::string(""),
			std::string("6BC1BEE22E409F96E93D7E117393172A"),
			std::string("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411"),
			std::string("6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710")
		};
		HexConverter::Decode(input, 4, m_input);

		const std::vector<std::string> expected =
		{
			std::string("BB1D6929E95937287FA37D129B756746"),
			std::string("070A16B46B4D4144F79BDD9DD04A287C"),
			std::string("DFA66747DE9AE63030CA32611497C827"),
			std::string("51F0BEBF7E3B9D92FC49741779363CFE"),
			std::string("D17DDF46ADAACDE531CAC483DE7A9367"),
			std::string("9E99A7BF31E710900662F65E617C5184"),
			std::string("8A1DE5BE2EB31AAD089A82E6EE908B0E"),
			std::string("A1D5DF0EED790F794D77589659F39A11"),
			std::string("028962F61B7BF89EFC6B551F4667D983"),
			std::string("28A7023F452E8F82BD4BF28D8C37C35C"),
			std::string("AAF3D8F1DE5640C232F5B169B9C911E6"),
			std::string("E1992190549F6ED5696A2C056C315410")
		};
		HexConverter::Decode(expected, 12, m_expected);
	}

	void CMACTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}