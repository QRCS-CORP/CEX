#include "HMACTest.h"
#include "../CEX/HMAC.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SHA2.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Exception::CryptoMacException;
	using Mac::HMAC;
	using Utility::IntegerTools;
	using Prng::SecureRandom;
	using Digest::SHA2;
	using Enumeration::SHA2Digests;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

	const std::string HMACTest::CLASSNAME = "HMACTest";
	const std::string HMACTest::DESCRIPTION = "RFC 4321 test vectors for HMAC SHA256, and SHA512.";
	const std::string HMACTest::SUCCESS = "SUCCESS! All HMAC tests have executed succesfully.";

	HMACTest::HMACTest()
		:
		m_expected(0),
		m_key(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	HMACTest::~HMACTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
	}

	const std::string HMACTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &HMACTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HMACTest::Run()
	{
		try
		{
			Ancillary();
			OnProgress(std::string("HMACTest: Passed the HMAC compact functions tests.."));

			Exception();
			OnProgress(std::string("HMACTest: Passed HMAC exception handling tests.."));

			HMAC* gen1 = new HMAC(SHA2Digests::SHA256);
			Kat(gen1, m_key[0], m_message[0], m_expected[0]);
			Kat(gen1, m_key[1], m_message[1], m_expected[1]);
			Kat(gen1, m_key[2], m_message[2], m_expected[2]);
			Kat(gen1, m_key[3], m_message[3], m_expected[3]);
			Kat(gen1, m_key[4], m_message[4], m_expected[4]);
			Kat(gen1, m_key[5], m_message[5], m_expected[5]);
			OnProgress(std::string("HMACTest: Passed HMAC SHA256 bit known answer vector tests.."));

			HMAC* gen2 = new HMAC(SHA2Digests::SHA512);
			Kat(gen2, m_key[0], m_message[0], m_expected[6]);
			Kat(gen2, m_key[1], m_message[1], m_expected[7]);
			Kat(gen2, m_key[2], m_message[2], m_expected[8]);
			Kat(gen2, m_key[3], m_message[3], m_expected[9]);
			Kat(gen2, m_key[4], m_message[4], m_expected[10]);
			Kat(gen2, m_key[5], m_message[5], m_expected[11]);
			OnProgress(std::string("HMACTest: Passed HMAC SHA512 bit known answer vector tests.."));

			Params(gen1);
			Params(gen2);
			OnProgress(std::string("HMACTest: Passed HMAC SHA256/SHA512 initialization parameters tests.."));

			Stress(gen1);
			Stress(gen2);
			OnProgress(std::string("HMACTest: Passed HMAC SHA256/SHA512 stress tests.."));

			delete gen1;
			delete gen2;

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoMacException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (CryptoException &ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void HMACTest::Ancillary()
	{
		std::vector<byte> otp(0);

		// HMAC-256

		otp.resize(m_expected[0].size());
		SHA2::MACR64P512(m_key[0], m_message[0], 0, m_message[0].size(), otp, 0);

		if (otp != m_expected[0])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR64P512"), std::string("Expected values don't match! -HA1"));
		}

		otp.resize(m_expected[1].size());
		SHA2::MACR64P512(m_key[1], m_message[1], 0, m_message[1].size(), otp, 0);

		if (otp != m_expected[1])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR64P512"), std::string("Expected values don't match! -HA2"));
		}

		otp.resize(m_expected[2].size());
		SHA2::MACR64P512(m_key[2], m_message[2], 0, m_message[2].size(), otp, 0);

		if (otp != m_expected[2])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR64P512"), std::string("Expected values don't match! -HA3"));
		}

		// HMAC-512

		otp.resize(m_expected[6].size());
		SHA2::MACR80P1024(m_key[0], m_message[0], 0, m_message[0].size(), otp, 0);

		if (otp != m_expected[6])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR80P1024"), std::string("Expected values don't match! -HA4"));
		}

		otp.resize(m_expected[7].size());
		SHA2::MACR80P1024(m_key[1], m_message[1], 0, m_message[1].size(), otp, 0);

		if (otp != m_expected[7])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR80P1024"), std::string("Expected values don't match! -HA5"));
		}

		otp.resize(m_expected[8].size());
		SHA2::MACR80P1024(m_key[2], m_message[2], 0, m_message[2].size(), otp, 0);

		if (otp != m_expected[8])
		{
			throw TestException(std::string("Ancillary"), std::string("MACR80P1024"), std::string("Expected values don't match! -HA6"));
		}
	}

	void HMACTest::Exception()
	{
		// test constructor -1
		try
		{
			// invalid cipher choice
			HMAC gen(SHA2Digests::None);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE1"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test constructor -2
		try
		{
			// invalid cipher choice
			HMAC gen(nullptr);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE2"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test initialization
		try
		{
			HMAC gen(SHA2Digests::SHA256);
			// invalid key size
			std::vector<byte> k(1);
			SymmetricKey kp(k);
			gen.Initialize(kp);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE3"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test finalize state -1
		try
		{
			HMAC gen(SHA2Digests::SHA256);
			std::vector<byte> code(gen.TagSize());
			// generator was not initialized
			gen.Finalize(code, 0);

			throw TestException(std::string("Exception"), gen.Name(), std::string("Exception handling failure! -HE4"));
		}
		catch (CryptoMacException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void HMACTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */
		const std::vector<std::string> key =
		{
			std::string("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"),
			std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			std::string("0102030405060708090A0B0C0D0E0F10111213141516171819"),
			std::string("0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C"),
			std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		};
		HexConverter::Decode(key, 6, m_key);

		const std::vector<std::string> message =
		{
			std::string("4869205468657265"),
			std::string("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
			std::string("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"),
			std::string("546573742057697468205472756E636174696F6E"),
			std::string("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374"),
			std::string("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C6172676572207468616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365642062792074686520484D414320616C676F726974686D2E")
		};
		HexConverter::Decode(message, 6, m_message);

		const std::vector<std::string> expected =
		{
			std::string("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7"),
			std::string("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE"),
			std::string("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B"),
			std::string("A3B6167473100EE06E0C796C2955552B"),
			std::string("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54"),
			std::string("9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2"),
			std::string("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854"),
			std::string("FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB"),
			std::string("B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD"),
			std::string("415FAD6271580A531D4179BC891D87A6"),
			std::string("80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598"),
			std::string("E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58")
		};
		HexConverter::Decode(expected, 12, m_expected);
		/*lint -restore */
	}

	void HMACTest::Kat(IMac* Generator, std::vector<byte> &Key, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> code(Generator->TagSize());
		SymmetricKey kp(Key);

		Generator->Initialize(kp);
		Generator->Update(Message, 0, Message.size());
		Generator->Finalize(code, 0);
		code.resize(Expected.size());

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), Generator->Name(), std::string("Expected values don't match! -HK1"));
		}
	}

	void HMACTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void HMACTest::Params(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> msg;
		std::vector<byte> otp1(Generator->TagSize());
		std::vector<byte> otp2(Generator->TagSize());
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
			msg.resize(MSGLEN);
			IntegerTools::Fill(key, 0, key.size(), rnd);
			IntegerTools::Fill(msg, 0, msg.size(), rnd);
			SymmetricKey kp(key);

			// generate the mac
			Generator->Initialize(kp);
			Generator->Compute(msg, otp1);
			Generator->Reset();
			Generator->Initialize(kp);
			Generator->Compute(msg, otp2);

			if (otp1 != otp2)
			{
				throw TestException(std::string("Params"), Generator->Name(), std::string("Returns a different array after reset! -HP1"));
			}
		}
	}

	void HMACTest::Stress(IMac* Generator)
	{
		SymmetricKeySize ks = Generator->LegalKeySizes()[0];
		std::vector<byte> msg;
		std::vector<byte> otp(Generator->TagSize());
		std::vector<byte> key(ks.KeySize());
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			try
			{
				const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXM_ALLOC, MINM_ALLOC));
				msg.resize(MSGLEN);
				IntegerTools::Fill(key, 0, key.size(), rnd);
				IntegerTools::Fill(msg, 0, msg.size(), rnd);
				SymmetricKey kp(key);

				// generate with the kdf
				Generator->Initialize(kp);
				Generator->Compute(msg, otp);
				Generator->Reset();
			}
			catch (CryptoException&)
			{
				throw;
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), Generator->Name(), std::string("The generator has thrown an exception! -HS1"));
			}
		}
	}
}
