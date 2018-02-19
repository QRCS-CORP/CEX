#include "HMACTest.h"
#include "../CEX/HMAC.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Key::Symmetric::SymmetricKey;

	const std::string HMACTest::DESCRIPTION = "RFC 4321 Test Vectors for HMAC SHA224, SHA256, SHA384, and SHA512.";
	const std::string HMACTest::FAILURE = "FAILURE! ";
	const std::string HMACTest::SUCCESS = "SUCCESS! All HMAC tests have executed succesfully.";

	HMACTest::HMACTest()
		:
		m_progressEvent()
	{
		Initialize();
	}

	HMACTest::~HMACTest()
	{
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
			CompareVector256(m_keys[0], m_input[0], m_exp256[0]);
			CompareVector256(m_keys[1], m_input[1], m_exp256[1]);
			CompareVector256(m_keys[2], m_input[2], m_exp256[2]);
			CompareVector256(m_keys[3], m_input[3], m_exp256[3]);
			CompareVector256(m_keys[4], m_input[4], m_exp256[4]);
			CompareVector256(m_keys[5], m_input[5], m_exp256[5]);
			CompareVector256(m_keys[6], m_input[6], m_exp256[6]);
			OnProgress(std::string("HMACTest: Passed SHA-2 256 bit known answer vector tests.."));

			CompareVector512(m_keys[0], m_input[0], m_exp512[0]);
			CompareVector512(m_keys[1], m_input[1], m_exp512[1]);
			CompareVector512(m_keys[2], m_input[2], m_exp512[2]);
			CompareVector512(m_keys[3], m_input[3], m_exp512[3]);
			CompareVector512(m_keys[4], m_input[4], m_exp512[4]);
			CompareVector512(m_keys[5], m_input[5], m_exp512[5]);
			CompareVector512(m_keys[6], m_input[6], m_exp512[6]);
			OnProgress(std::string("HMACTest: Passed SHA-2 512 bit known answer vector tests.."));

			CompareAccess(m_keys[3]);
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

	void HMACTest::CompareAccess(std::vector<byte> &Key)
	{
		std::vector<byte> hash1(32);
		Digest::SHA256* eng = new Digest::SHA256();
		Mac::HMAC mac(eng);
		SymmetricKey kp(Key);

		mac.Initialize(kp);

		std::vector<byte> input(256);
		for (size_t i = 0; i < input.size(); ++i)
		{
			input[i] = (byte)i;
		}

		mac.Compute(input, hash1);

		std::vector<byte> hash2(32);
		mac.Update(input, 0, 128);
		mac.Update(input, 128, 128);
		mac.Finalize(hash2, 0);
		delete eng;

		if (hash1 != hash2)
		{
			throw TestException("CMAC is not equal!");
		}
	}

	void HMACTest::CompareVector256(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash(32, 0);
		Digest::SHA256* eng = new Digest::SHA256();
		Mac::HMAC mac(eng);
		SymmetricKey kp(Key);

		mac.Initialize(kp);
		mac.Compute(Input, hash);

		delete eng;

		// truncated output, test case #5
		if (Expected.size() != 32)
		{
			std::vector<byte> tmph;
			tmph.resize(Expected.size(), 0);
			std::memcpy(&tmph[0], &hash[0], Expected.size());

			if (Expected != tmph)
			{
				throw TestException("HMACTest: return code is not equal!");
			}
		}
		else
		{
			if (Expected != hash)
			{
				throw TestException("HMACTest: return code is not equal!");
			}
		}
	}

	void HMACTest::CompareVector512(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash(32, 0);
		Digest::SHA512* eng = new Digest::SHA512();
		Mac::HMAC mac(eng);
		SymmetricKey kp(Key);

		mac.Initialize(kp);
		mac.Compute(Input, hash);

		delete eng;

		if (Expected.size() != 64)
		{
			std::vector<byte> tmph;
			tmph.resize(Expected.size(), 0);
			std::memcpy(&tmph[0], &hash[0], Expected.size());

			if (Expected != tmph)
			{
				throw TestException("HMACTest: return code is not equal!");
			}
		}
		else
		{
			if (Expected != hash)
			{
				throw TestException("HMACTest: return code is not equal!");
			}
		}
	}

	void HMACTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */
		const std::vector<std::string> keys =
		{
			std::string("0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B"),
			std::string("4A656665"),
			std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			std::string("0102030405060708090A0B0C0D0E0F10111213141516171819"),
			std::string("0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C0C"),
			std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			std::string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
		};
		HexConverter::Decode(keys, 7, m_keys);

		const std::vector<std::string> input =
		{
			std::string("4869205468657265"),
			std::string("7768617420646F2079612077616E7420666F72206E6F7468696E673F"),
			std::string("DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"),
			std::string("CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"),
			std::string("546573742057697468205472756E636174696F6E"),
			std::string("54657374205573696E67204C6172676572205468616E20426C6F636B2D53697A65204B6579202D2048617368204B6579204669727374"),
			std::string("5468697320697320612074657374207573696E672061206C6172676572207468616E20626C6F636B2D73697A65206B657920616E642061206C61726765722074"
				"68616E20626C6F636B2D73697A6520646174612E20546865206B6579206E6565647320746F20626520686173686564206265666F7265206265696E6720757365"
				"642062792074686520484D414320616C676F726974686D2E")
		};
		HexConverter::Decode(input, 7, m_input);

		const std::vector<std::string> exp256 =
		{
			std::string("B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32CFF7"),
			std::string("5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843"),
			std::string("773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED565FE"),
			std::string("82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729665B"),
			std::string("A3B6167473100EE06E0C796C2955552B"),
			std::string("60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE37F54"),
			std::string("9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A35E2")
		};
		HexConverter::Decode(exp256, 7, m_exp256);

		const std::vector<std::string> exp512 =
		{
			std::string("87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E17CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C203A126854"),
			std::string("164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA2505549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A38BCE737"),
			std::string("FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B2279D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859E13292FB"),
			std::string("B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361EE3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB10A298DD"),
			std::string("415FAD6271580A531D4179BC891D87A6"),
			std::string("80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A985D786598"),
			std::string("E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CDC944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440FA8C6A58")
		};
		HexConverter::Decode(exp512, 7, m_exp512);
		/*lint -restore */
	}

	void HMACTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
