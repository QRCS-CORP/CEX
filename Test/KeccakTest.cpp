#include "KeccakTest.h"
#include "../CEX/HMAC.h"
#include "../CEX/Keccak256.h"
#include "../CEX/Keccak512.h"
#include "../CEX/Keccak1024.h"
#include "../CEX/SymmetricKey.h"

//#define ENABLE_LONGKAT_TEST

namespace Test
{
	using namespace Digest;
	using CEX::Key::Symmetric::SymmetricKey;
	using CEX::Mac::HMAC;

	const std::string KeccakTest::DESCRIPTION = "Keccak Vector KATs; tests SHA-3 224/256/384/512 and HMACs.";
	const std::string KeccakTest::FAILURE = "FAILURE! ";
	const std::string KeccakTest::SUCCESS = "SUCCESS! All Keccak tests have executed succesfully.";

	KeccakTest::KeccakTest()
		:
		m_messages(0),
		m_expected256(0),
		m_expected512(0),
		m_macKeys(0),
		m_macData(0),
		m_mac256(0),
		m_mac512(0),
		m_progressEvent(),
		m_truncKey(0),
		m_truncData(0),
		m_trunc256(0),
		m_trunc512(0),
		m_xtremeData(0)
	{
	}

	KeccakTest::~KeccakTest()
	{
	}

	const std::string KeccakTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KeccakTest::Progress()
	{
		return m_progressEvent;
	}

	std::string KeccakTest::Run()
	{
		try
		{
			Initialize();

			TreeParamsTest();
			OnProgress(std::string("Passed KeccakParams parameter serialization test.."));

			Keccak256* kc256 = new Keccak256;
			Keccak512* kc512 = new Keccak512;
			Keccak1024* kc1024 = new Keccak1024;

			CompareVector(kc256, m_expected256);
			OnProgress(std::string("Passed Keccak 256 bit digest vector tests.."));
			CompareVector(kc512, m_expected512);
			OnProgress(std::string("KeccakTest: Passed Keccak 512 bit digest vector tests.."));
			CompareVector(kc1024, m_expected1024);
			OnProgress(std::string("KeccakTest: Passed Keccak 1024 bit digest vector tests.."));

			// TODO: add parallel tests

			CompareHMAC(kc256, m_mac256, m_trunc256);
			OnProgress(std::string("Passed Keccak 256 bit digest HMAC tests.."));
			CompareHMAC(kc512, m_mac512, m_trunc512);
			OnProgress(std::string("KeccakTest: Passed Keccak 512 bit digest HMAC tests.."));
			CompareHMAC(kc1024, m_mac1024, m_trunc1024);
			OnProgress(std::string("KeccakTest: Passed Keccak 1024 bit digest HMAC tests.."));

			delete kc256;
			delete kc512;
			delete kc1024;

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

	void KeccakTest::CompareVector(IDigest* Digest, std::vector<std::vector<byte>> &Expected)
	{
		std::vector<byte> hash(Digest->DigestSize(), 0);

		for (size_t i = 0; i != m_messages.size(); i++)
		{
			if (m_messages[i].size() != 0)
			{
				Digest->Update(m_messages[i], 0, m_messages[i].size());
			}

			Digest->Finalize(hash, 0);

			if (Expected[i] != hash)
			{
				throw TestException("Keccak: Expected hash is not equal!");
			}
		}

		std::vector<byte> k64(1024 * 64, 0);

		for (size_t i = 0; i != k64.size(); i++)
		{
			k64[i] = (byte)'a';
		}

		Digest->Update(k64, 0, k64.size());
		Digest->Finalize(hash, 0);

		if (Expected[m_messages.size()] != hash)
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		for (size_t i = 0; i != k64.size(); i++)
		{
			Digest->Update((byte)'a');
		}

		Digest->Finalize(hash, 0);

		if (Expected[m_messages.size()] != hash)
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		for (size_t i = 0; i != k64.size(); i++)
		{
			k64[i] = (byte)('a' + (i % 26));
		}

		Digest->Update(k64, 0, k64.size());
		Digest->Finalize(hash, 0);

		if (Expected[m_messages.size() + 1] != hash)
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		for (size_t i = 0; i != 64; i++)
		{
			Digest->Update(k64[i * 1024]);
			Digest->Update(k64, i * 1024 + 1, 1023);
		}

		Digest->Finalize(hash, 0);

		if (Expected[m_messages.size() + 1] != hash)
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}

		CompareDoFinal(Digest);

#if defined(ENABLE_LONGKAT_TEST)
		// very long test (it passes)
		for (size_t i = 0; i != 16384; i++)
		{
			for (int j = 0; j != 1024; j++)
			{
				Digest->Update(m_xtremeData, 0, m_xtremeData.size());
			}
		}

		Digest->Finalize(hash, 0);

		if ((Expected[m_messages.size() + 2]) != hash)
		{
			throw TestException("Keccak: Expected hash is not equal!");
		}
#endif
	}

	void KeccakTest::CompareDoFinal(IDigest* Digest)
	{
		std::vector<byte> hash(Digest->DigestSize(), 0);

		Digest->Finalize(hash, 0);

		for (size_t i = 0; i <= Digest->DigestSize(); ++i)
		{
			std::vector<byte> expected(2 * Digest->DigestSize(), 0);
			std::memcpy(&expected[i], &hash[0], hash.size());
			std::vector<byte> outBytes(2 * Digest->DigestSize(), 0);

			Digest->Finalize(outBytes, i);

			if (expected != outBytes)
			{
				throw TestException("Keccak Finalize: Expected hash is not equal!");
			}
		}
	}

	void KeccakTest::CompareHMAC(IDigest* Digest, std::vector<std::vector<byte>> &Expected, std::vector<byte> &TruncExpected)
	{
		HMAC mac(Digest);
		std::vector<byte> macV2(mac.MacSize(), 0);
		std::string ret = "";

		for (size_t i = 0; i != m_macKeys.size(); i++)
		{
			SymmetricKey kp(m_macKeys[i]);
			mac.Initialize(kp);
			mac.Update(m_macData[i], 0, m_macData[i].size());
			std::vector<byte> macV(mac.MacSize());
			mac.Finalize(macV, 0);

			if (Expected[i] != macV)
			{
				throw TestException("Keccak HMAC: Expected hash is not equal!");
			}
		}

		// test truncated keys
		HMAC mac2(Digest);
		SymmetricKey kp(m_truncKey);
		mac2.Initialize(kp);
		mac2.Update(m_truncData, 0, m_truncData.size());
		mac2.Finalize(macV2, 0);

		for (size_t i = 0; i != TruncExpected.size(); i++)
		{
			if (macV2[i] != TruncExpected[i])
			{
				throw TestException("Keccak HMAC: Expected hash is not equal!");
			}
		}
	}

	void KeccakTest::Initialize()
	{
		const char* messagesEnc[3] =
		{
			(""),
			("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"),
			("54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e")
		};
		HexConverter::Decode(messagesEnc, 3, m_messages);

		const char* expected256Enc[6] =
		{
			("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
			("4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"),
			("578951e24efd62a3d63a86f7cd19aaa53c898fe287d2552133220370240b572d"),
			("0047a916daa1f92130d870b542e22d3108444f5a7e4429f05762fb647e6ed9ed"),
			("db368762253ede6d4f1db87e0b799b96e554eae005747a2ea687456ca8bcbd03"),
			("5f313c39963dcf792b5470d4ade9f3a356a3e4021748690a958372e2b06f82a4")
		};
		HexConverter::Decode(expected256Enc, 6, m_expected256);

		const char* expected512Enc[6] =
		{
			("0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e"),
			("d135bb84d0439dbac432247ee573a23ea7d3c9deb2a968eb31d47c4fb45f1ef4422d6c531b5b9bd6f449ebcc449ea94d0a8f05f62130fda612da53c79659f609"),
			("ab7192d2b11f51c7dd744e7b3441febf397ca07bf812cceae122ca4ded6387889064f8db9230f173f6d1ab6e24b6e50f065b039f799f5592360a6558eb52d760"),
			("34341ead153aa1d1fdcf6cf624c2b4f6894b6fd16dc38bd4ec971ac0385ad54fafcb2e0ed86a1e509456f4246fdcb02c3172824cd649d9ad54c51f7fb49ea67c"),
			("dc44d4f4d36b07ab5fc04016cbe53548e5a7778671c58a43cb379fd00c06719b8073141fc22191ffc3db5f8b8983ae8341fa37f18c1c969664393aa5ceade64e"),
			("3e122edaf37398231cfaca4c7c216c9d66d5b899ec1d7ac617c40c7261906a45fc01617a021e5da3bd8d4182695b5cb785a28237cbb167590e34718e56d8aab8")
		};
		HexConverter::Decode(expected512Enc, 6, m_expected512);

		// note: this is an original kat-set
		const char* expected1024Enc[6] =
		{
			("4ed0ad69e8cd211d65e2c0158b67ae4f86263b5014ab79fff1471885303cb79fbe78f8281310234e893b564f3e964f1d66dd6a24006da3e9111f62aac7e73fbdae5199bc6a07eec52acc0636a294bd1b2e8d749ad0a015b7f3a8278fdcbc92252e7f0fd1900af709b597ff1c419b0a733e7018347e8504173c457edaeb19ddb5"),
			("04ddc8ff4a0ebeedbc37e9a044cb3ef3a8f250225747e83f280044f10a37724fa570bd59006d9b641209e04fddde79bfbedd306db759aba64496d999d486b9b8b64196e93cf0d1a59e9cfb583a8ec1f5fad13cf746174a7bf41d802bd39a38e749cc5b7ccf32f80cd07548a9b104e526e63837df637e7baf0b44fae23cfe729b"),
			("5c3092ad41d4b5477eb781d4764dc73904029999ded12e760098827c0eb5732c2c1a4a6cf0503e43f87cc447c1651ca4c8152bb21a2084b5893989809aa4fe8f1e17b216f91fe2ee2111a0b939a2ad090bd9dc1ef7c4a1f85a1ad1ce1376d9665bf1c5424b6466b3146be185da89a6546fdd8aa1524039b7077a109f9cf90fea"),
			("424be4b5ab9291d45952e4de138db20782b478e0401ac3d6299bab3735c5b4477fcc34b39ca58d0f50078dc51f1ca51a6e749c4cd047c99ac1298aefc675a8912d74d113843afa205665bdc9ed47811addb0c0530ad767d1bead9296049d46d3b6dd092216fd65183dd9a728d31738ba09180aaeb43c4b1cb39b95b04445a97c"),
			("8bca0faa51893c9fdacc7c26ed623ddb8009a1aa9afd2df7fbdb911160fa8d9728ef97f7347751711d41d43e012973a0f8e5193b27117a8683818d4fdd05b05744f0cd20f064d217ca757c872de0b90ab8bed5637f8d25d631319914a82142fa0ff0d721b19d67ab1ecb8aa1c3bf62c55f24a4169c16a39330e432c99b7edcb0"),
			("a3becd77b98cf5ac678a47cd2e76572ddd982eef4cb2040fb72331d3c2fc9d4d2cd8c4e3840b361acc8fc80b17cb1b8dff4d016012d58b6fc87210da3a244bafb26dff66f4f4309257a427f0b423e2e3f6aa1b5febae817d98e55bd3beca224852f5d3e3d93bc2145082db11e43457d8a56d57aa54a5b433c9c21ee7ecda1fdb")
		};
		HexConverter::Decode(expected1024Enc, 6, m_expected1024);

		const char* macKeysEnc[7] =
		{
			("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
			("4a656665"),
			("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			("0102030405060708090a0b0c0d0e0f10111213141516171819"),
			("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
			"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
				("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
					"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
					("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
						"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
		};
		HexConverter::Decode(macKeysEnc, 7, m_macKeys);

		const char* macDataEnc[7] =
		{
			("4869205468657265"),
			("7768617420646f2079612077616e7420666f72206e6f7468696e673f"),
			("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
			("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"),
			("54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374"),
			("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" \
			"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365" \
				"642062792074686520484d414320616c676f726974686d2e"),
				("5468697320697320612074657374207573696e672061206c6172676572207468616e20626c6f636b2d73697a65206b657920616e642061206c61726765722074" \
					"68616e20626c6f636b2d73697a6520646174612e20546865206b6579206e6565647320746f20626520686173686564206265666f7265206265696e6720757365\n" \
					"642062792074686520484d414320616c676f726974686d2e")
		};
		HexConverter::Decode(macDataEnc, 7, m_macData);

		const char* mac256Enc[7] =
		{
			("9663d10c73ee294054dc9faf95647cb99731d12210ff7075fb3d3395abfb9821"),
			("aa9aed448c7abc8b5e326ffa6a01cdedf7b4b831881468c044ba8dd4566369a1"),
			("95f43e50f8df80a21977d51a8db3ba572dcd71db24687e6f86f47c1139b26260"),
			("6331ba9b4af5804a68725b3663eb74814494b63c6093e35fb320a85d507936fd"),
			("b4d0cdee7ec2ba81a88b86918958312300a15622377929a054a9ce3ae1fac2b6"),
			("1fdc8cb4e27d07c10d897dec39c217792a6e64fa9c63a77ce42ad106ef284e02"),
			("fdaa10a0299aecff9bb411cf2d7748a4022e4a26be3fb5b11b33d8c2b7ef5484")
		};
		HexConverter::Decode(mac256Enc, 7, m_mac256);

		const char* mac512Enc[7] =
		{
			("8852c63be8cfc21541a4ee5e5a9a852fc2f7a9adec2ff3a13718ab4ed81aaea0b87b7eb397323548e261a64e7fc75198f6663a11b22cd957f7c8ec858a1c7755"),
			("c2962e5bbe1238007852f79d814dbbecd4682e6f097d37a363587c03bfa2eb0859d8d9c701e04cececfd3dd7bfd438f20b8b648e01bf8c11d26824b96cebbdcb"),
			("eb0ed9580e0ec11fc66cbb646b1be904eaff6da4556d9334f65ee4b2c85739157bae9027c51505e49d1bb81cfa55e6822db55262d5a252c088a29a5e95b84a66"),
			("b46193bb59f4f696bf702597616da91e2a4558a593f4b015e69141ba81e1e50ea580834c2b87f87baa25a3a03bfc9bb389847f2dc820beae69d30c4bb75369cb"),
			("d05888a6ebf8460423ea7bc85ea4ffda847b32df32291d2ce115fd187707325c7ce4f71880d91008084ce24a38795d20e6a28328a0f0712dc38253370da3ebb5"),
			("2c6b9748d35c4c8db0b4407dd2ed2381f133bdbd1dfaa69e30051eb6badfcca64299b88ae05fdbd3dd3dd7fe627e42e39e48b0fe8c7f1e85f2dbd52c2d753572"),
			("6adc502f14e27812402fc81a807b28bf8a53c87bea7a1df6256bf66f5de1a4cb741407ad15ab8abc136846057f881969fbb159c321c904bfb557b77afb7778c8")
		};
		HexConverter::Decode(mac512Enc, 7, m_mac512);

		// note: this is an original kat-set
		const char* mac1024Enc[7] =
		{
			("42805c510f82fd49e3ac858b1d53d42de7214823febb9794feb2c2e01fceabce0f0027c82afacf5ecebc1a60877d543248a5ed6af1e306116682dae1ece0ff3b35325004cb59e6982b133ff5f41dae2fc4b0171f117393531af4c98ffb2a353b21f22f301de64a23ae6d09710a03a26f14f122132823bac930af7b39eb8d95da"),
			("e5b8b469a82653ccc186e7b23ff1ccd0e16eee7d950ec56b7343237be39bfa963179948b1c85551c31821476efae2b7fbf6aebe0e5d2ebda32502fa524e4b296aa1cfd0e7bba76fc0f8860a33367a1d21ad4cfa45ae0490f26a8d7613caedc67f7ab706662364451740eacd399b4407bd7dddda38cda0eea90e69107e14fb064"),
			("9656e52c565bae75b19260211519d09d185cfd3a8f846fa643b123f4bc1bd7609762ec0dfe61f8cf87570ce77e7021bad356266a80ac02d41c754ff7b786500830d3187b5407877b97c599a52ade3c568e611cf2edaa721295b34dc5145f7af290bf460ebe726ee451d0d633ff2d09faa5384744bdb7fbb2b56f989320c98204"),
			("469d9fbb6df60ff2058ae9a49946f62ffc6da5b5752ba1c91480e143a9c0e776e7c322c7c2813cb3589d329548b2f177f0f98073aa54fc4c70b26e1056656af9d9e01ab174da9c23072c46f3a57b0bef5fe2ce2d8b9dfe41248fd7118d8644b783b806dbdf3e3f32a0598229e4713d44ef4671aa9b4df4026468c85ba61c57b6"),
			("83befc14425f9140334df3ae73b007073e78b17a338210bc464856fb4527ca63c64efa81fa305a00a9c3902e965dfd4869e18210bab7fe2e2c7f40bb0bead5d2cd14405bada15c637bb26dac378bcd6a1cc2853577259b753865f6175ed278ddceabb23868b5f9dbbce0e19f5df6e897d56c4d069f4425fd85cc944506350ac3"),
			("c5836097ffb8344c595146a15ad6c9103d57c565f2ca693f0efaab8e7e9b9345c21cf056b0a66238f0691be0b96f7fd31ac0157dcab016b183c07c1539c0ed9a522135c168f0e6a2893bceeab84fa38a4f4b13312fb0e07534ad85fd88931fc1ee517bfd84ebeb0585ad28ddc5859bb187e832fcaf09ff7f68c4dc63bc0d5092"),
			("26e07c5d1badfd4fcdda85f22595f09a57c54fc49856e87621afa9ed4dd3ede5412b37a2b2ed57ca7f18fd604e4fb341e56d0b469326ccc4f6e3025d4f3e0629bd0a5cf89242fa892a51872bf42b9fbda0fdf93643d39cbda6d9fb3737e109ab91352745f1262089804f613bf0f9f5d76197b4f58f0fa1bc569ea45cc9290b3e")
		};
		HexConverter::Decode(mac1024Enc, 7, m_mac1024);

		HexConverter::Decode("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c", m_truncKey);
		HexConverter::Decode("546573742057697468205472756e636174696f6e", m_truncData);
		HexConverter::Decode("745e7e687f8335280d54202ef13cecc6", m_trunc256);
		HexConverter::Decode("04c929fead434bba190dacfa554ce3f5", m_trunc512);
		HexConverter::Decode("13546420cecd906398c95da09ac9880cb171ff43a367ef5c8354343c0d670665752fa4e5a69312994455e2f6d66aad941c8dd83818c539678c973112ff745c0e7e1ba1f314cf5e9f1aa7b21866ebd6fb21c502c5f344f18bb544f95f2aa95d0178800871302e7515872597ee2b1f0c7f32d56714dd991c1c0be96a243001a752", m_trunc1024);
		HexConverter::Decode("61626364656667686263646566676869636465666768696a6465666768696a6b65666768696a6b6c666768696a6b6c6d6768696a6b6c6d6e68696a6b6c6d6e6f", m_xtremeData);
	}

	void KeccakTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void KeccakTest::TreeParamsTest()
	{
		std::vector<byte> code1(8, 7);

		KeccakParams tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		KeccakParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw std::string("KeccakTest: Tree parameters test failed!");
		}

		std::vector<byte> code2(20, 7);
		KeccakParams tree3(0, 64, 1, 128, 8, 1, code2);
		tres = tree3.ToBytes();
		KeccakParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw std::string("KeccakTest: Tree parameters test failed!");
		}
	}
}