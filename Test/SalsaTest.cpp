#include "SalsaTest.h"
#include "../CEX/CSP.h"
#include "../CEX/Salsa20.h"

namespace Test
{
	using namespace Cipher::Symmetric::Stream;

	const std::string SalsaTest::DESCRIPTION = "Salsa20 Known Answer Tests.";
	const std::string SalsaTest::FAILURE = "FAILURE! ";
	const std::string SalsaTest::SUCCESS = "SUCCESS! Salsa20 tests have executed succesfully.";

	SalsaTest::SalsaTest()
		:
		m_progressEvent()
	{
		Initialize();
	}

	SalsaTest::~SalsaTest()
	{
	}

	const std::string SalsaTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SalsaTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SalsaTest::Run()
	{
		try
		{
			// test vectors with 8/12/20 rounds and 128/256 keys
			CompareVector(20, m_key[0], m_iv[0], m_plainText, m_cipherText[0]);
			CompareVector(20, m_key[1], m_iv[0], m_plainText, m_cipherText[1]);
			OnProgress(std::string("SalsaTest: Passed 20 round vector tests.."));
			CompareVector(12, m_key[0], m_iv[0], m_plainText, m_cipherText[2]);
			CompareVector(8, m_key[0], m_iv[0], m_plainText, m_cipherText[3]);
			OnProgress(std::string("SalsaTest: Passed 8 and 12 round vector tests.."));
			CompareVector(20, m_key[2], m_iv[1], m_plainText, m_cipherText[4]);
			CompareVector(20, m_key[3], m_iv[2], m_plainText, m_cipherText[5]);
			OnProgress(std::string("SalsaTest: Passed 256 bit key vector tests.."));

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

	void SalsaTest::CompareParallel()
	{
		Provider::CSP rng;
		std::vector<byte> key(32);
		rng.GetBytes(key);
		std::vector<byte> iv(8);
		rng.GetBytes(iv);
		std::vector<byte> data(10240);
		rng.GetBytes(data);
		std::vector<byte> enc(10240, 0);
		std::vector<byte> dec(10240, 0);
		std::vector<byte> enc2(10240, 0);
		std::vector<byte> dec2(10240, 0);
		Key::Symmetric::SymmetricKey k(key, iv);
		
		// encrypt linear
		Salsa20 cipher(20);
		cipher.Initialize(k);
		cipher.ParallelProfile().IsParallel() = false;
		cipher.Transform(data, 0, enc, 0, data.size());

		// encrypt parallel
		Salsa20 cipher2(20);
		cipher2.Initialize(k);
		cipher2.ParallelProfile().IsParallel() = true;
		cipher2.ParallelProfile().ParallelBlockSize() = cipher2.ParallelProfile().ParallelMinimumSize();
		cipher2.Transform(data, 0, enc2, 0, data.size());

		if (enc != enc2)
		{
			throw TestException("Salsa20: Encrypted arrays are not equal!");
		}

		// decrypt linear
		cipher2.Initialize(k);
		cipher2.ParallelProfile().IsParallel() = false;
		cipher2.Transform(enc, 0, dec, 0, enc.size());

		// decrypt parallel
		cipher.Initialize(k);
		cipher.ParallelProfile().IsParallel() = true;
		cipher.ParallelProfile().ParallelBlockSize() = cipher.ParallelProfile().ParallelMinimumSize();
		cipher.Transform(enc2, 0, dec2, 0, enc2.size());

		if (dec != data)
		{
			throw TestException("Salsa20: Decrypted arrays are not equal!");
		}
		if (dec != dec2)
		{
			throw TestException("Salsa20: Decrypted arrays are not equal!");
		}
	}

	void SalsaTest::CompareVector(int Rounds, std::vector<byte> &Key, std::vector<byte> &Vector, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		Key::Symmetric::SymmetricKey k(Key, Vector);
		Salsa20 cipher(Rounds);
		cipher.Initialize(k);
		cipher.Transform(Input, 0, outBytes, 0, Input.size());

		if (outBytes != Output)
		{
			throw TestException("Salsa20: Encrypted arrays are not equal!");
		}

		if (!Test::TestUtils::IsEqual(outBytes, Output))
		{
			throw TestException("Salsa20: Encrypted arrays are not equal!");
		}

		cipher.Initialize(k);
		cipher.Transform(Output, 0, outBytes, 0, Output.size());

		if (!Test::TestUtils::IsEqual(outBytes, Input))
		{
			throw TestException("Salsa20: Decrypted arrays are not equal!");
		}
	}

	void SalsaTest::Initialize()
	{
		/*lint -save -e417 */
		HexConverter::Decode(std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"), m_plainText);

		const std::vector<std::string> keys =
		{
			std::string("80000000000000000000000000000000"),//20-1
			std::string("00400000000000000000000000000000"),//20-2
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12")
		};
		HexConverter::Decode(keys, 4, m_key);

		const std::vector<std::string> ivs =
		{
			std::string("0000000000000000"),
			std::string("0D74DB42A91077DE"),
			std::string("167DE44BB21980E7")
		};
		HexConverter::Decode(ivs, 3, m_iv);

		const std::vector<std::string> cipherText =
		{
			std::string("4DFA5E481DA23EA09A31022050859936DA52FCEE218005164F267CB65F5CFD7F2B4F97E0FF16924A52DF269515110A07F9E460BC65EF95DA58F740B7D1DBB0AA"), //20r-1
			std::string("0471076057830FB99202291177FBFE5D38C888944DF8917CAB82788B91B53D1CFB06D07A304B18BB763F888A61BB6B755CD58BEC9C4CFB7569CB91862E79C459"), //20r-2
			std::string("FC207DBFC76C5E1774961E7A5AAD09069B2225AC1CE0FE7A0CE77003E7E5BDF8B31AF821000813E6C56B8C1771D6EE7039B2FBD0A68E8AD70A3944B677937897"), //12r
			std::string("A9C9F888AB552A2D1BBFF9F36BEBEB337A8B4B107C75B63BAE26CB9A235BBA9D784F38BEFC3ADF4CD3E266687EA7B9F09BA650AE81EAC6063AE31FF12218DDC5"), //8r
			std::string("F5FAD53F79F9DF58C4AEA0D0ED9A9601F278112CA7180D565B420A48019670EAF24CE493A86263F677B46ACE1924773D2BB25571E1AA8593758FC382B1280B71"), //20r-256k
			std::string("3944F6DC9F85B128083879FDF190F7DEE4053A07BC09896D51D0690BD4DA4AC1062F1E47D3D0716F80A9B4D85E6D6085EE06947601C85F1A27A2F76E45A6AA87")  //20r-256k
		};
		HexConverter::Decode(cipherText, 6, m_cipherText);
		/*lint -restore */
	}

	void SalsaTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}