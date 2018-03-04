#include "KMACTest.h"
#include "../CEX/KMAC.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Mac::KMAC;
	using Key::Symmetric::SymmetricKey;

	const std::string KMACTest::DESCRIPTION = "SP800-185 Test Vectors for KMAC-128 and KMAC-256.";
	const std::string KMACTest::FAILURE = "FAILURE! ";
	const std::string KMACTest::SUCCESS = "SUCCESS! All KMAC tests have executed succesfully.";

	KMACTest::KMACTest()
		:
		m_progressEvent()
	{
		Initialize();
	}

	KMACTest::~KMACTest()
	{
	}

	const std::string KMACTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KMACTest::Progress()
	{
		return m_progressEvent;
	}

	std::string KMACTest::Run()
	{
		try
		{
			KMAC* gen1 = new KMAC(Enumeration::ShakeModes::SHAKE128);
			CompareVector(gen1, m_custom[0], m_message[0], m_expected[0]);
			CompareVector(gen1, m_custom[1], m_message[0], m_expected[1]);
			CompareVector(gen1, m_custom[1], m_message[1], m_expected[2]);
			delete gen1;

			OnProgress(std::string("KMACTest: Passed KMAC-128 known answer vector tests.."));

			KMAC* gen2 = new KMAC(Enumeration::ShakeModes::SHAKE256);
			CompareVector(gen2, m_custom[1], m_message[0], m_expected[3]);
			CompareVector(gen2, m_custom[0], m_message[1], m_expected[4]);
			CompareVector(gen2, m_custom[1], m_message[1], m_expected[5]);
			delete gen2;

			OnProgress(std::string("KMACTest: Passed KMAC-256 known answer vector tests.."));

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

	void KMACTest::CompareVector(Mac::IMac* Generator, std::vector<byte> &Custom, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> output(Expected.size());
		SymmetricKey kp(m_key, Custom);
		std::vector<byte> output1(Expected.size());
		std::vector<byte> output2(Expected.size());

		Generator->Initialize(kp);
		Generator->Update(Input, 0, Input.size());
		Generator->Finalize(output1, 0);

		if (output1 != Expected)
		{
			throw TestException("KMACTest: return code is not equal!");
		}

		Generator->Initialize(kp);
		Generator->Compute(Input, output2);

		if (output2 != Expected)
		{
			throw TestException("KMACTest: return code is not equal!");
		}
	}

	void KMACTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */

		HexConverter::Decode(std::string("404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"), m_key);

		const std::vector<std::string> custom =
		{
			std::string(""),
			std::string("4D7920546167676564204170706C69636174696F6E")
		};
		HexConverter::Decode(custom, 2, m_custom);

		const std::vector<std::string> message =
		{
			std::string("00010203"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
				"404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
				"808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
				"C0C1C2C3C4C5C6C7")
		};
		HexConverter::Decode(message, 2, m_message);

		const std::vector<std::string> expected =
		{
			std::string("E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"),
			std::string("3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"),
			std::string("1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"),
			std::string("20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"),
			std::string("75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"),
			std::string("B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965"),
		};
		HexConverter::Decode(expected, 6, m_expected);

		/*lint -restore */
	}

	void KMACTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
