#include "SkeinTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/Skein.h"
#include "../CEX/Skein256.h"
#include "../CEX/Skein512.h"
#include "../CEX/Skein1024.h"
#include "../CEX/SecureRandom.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Exception::CryptoDigestException;
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
	using Digest::Skein;
	using Digest::Skein256;
	using Digest::Skein512;
	using Digest::Skein1024;
	using Digest::SkeinParams;
#if defined(__AVX2__)
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string SkeinTest::CLASSNAME = "SkeinTest";
	const std::string SkeinTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of Skein.";
	const std::string SkeinTest::SUCCESS = "SUCCESS! All Skein tests have executed succesfully.";

	//~~~Constructor~~~//

	SkeinTest::SkeinTest()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	SkeinTest::~SkeinTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_message);
	}

	//~~~Accessors~~~//

	const std::string SkeinTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SkeinTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string SkeinTest::Run()
	{
		try
		{
			CpuDetect detect;

			Exception();
			OnProgress(std::string("SkeinTest: Passed Skein-256/512/1024 exception handling tests.."));

			Skein256* dgt256s = new Skein256();
			Kat(dgt256s, m_message[0], m_expected[0]);
			Kat(dgt256s, m_message[1], m_expected[1]);
			Kat(dgt256s, m_message[2], m_expected[2]);
			OnProgress(std::string("SkeinTest: Passed Skein-256 digest vector tests.."));

			Skein512* dgt512s = new Skein512();
			Kat(dgt512s, m_message[3], m_expected[3]);
			Kat(dgt512s, m_message[4], m_expected[4]);
			Kat(dgt512s, m_message[5], m_expected[5]);
			OnProgress(std::string("SkeinTest: Passed Skein-512 digest vector tests.."));

			Skein1024* dgt1024s = new Skein1024();
			Kat(dgt1024s, m_message[6], m_expected[6]);
			Kat(dgt1024s, m_message[7], m_expected[7]);
			Kat(dgt1024s, m_message[8], m_expected[8]);
			OnProgress(std::string("SkeinTest: Passed Skein-1024 digest vector tests.."));

			Stress(dgt256s);
			OnProgress(std::string("SkeinTest: Passed Skein-256 sequential stress tests.."));
			delete dgt256s;

			Stress(dgt512s);
			OnProgress(std::string("SkeinTest: Passed Skein-512 sequential stress tests.."));
			delete dgt512s;

			Stress(dgt1024s);
			OnProgress(std::string("SkeinTest: Passed Skein-1024 sequential stress tests.."));
			delete dgt1024s;

			Skein256* dgt256p = new Skein256(true);
			Stress(dgt256p);
			OnProgress(std::string("SkeinTest: Passed Skein-256 parallel stress tests.."));

			Skein512* dgt512p = new Skein512(true);
			Stress(dgt512p);
			OnProgress(std::string("SkeinTest: Passed Skein-512 parallel stress tests.."));

			Skein1024* dgt1024p = new Skein1024(true);
			Stress(dgt1024p);
			OnProgress(std::string("SkeinTest: Passed Skein-1024 parallel stress tests.."));

			Parallel(dgt256p);
			OnProgress(std::string("SkeinTest: Passed Skein-256 parallel integrity tests.."));
			delete dgt256p;

			Parallel(dgt512p);
			delete dgt512p;
			OnProgress(std::string("SkeinTest: Passed Skein-512 parallel integrity tests.."));

			Parallel(dgt1024p);
			delete dgt1024p;
			OnProgress(std::string("SkeinTest: Passed Skein-1024 parallel integrity tests.."));

			PermutationR72();
			OnProgress(std::string("SkeinTest: Passed Skein 72 round permutation variants equivalence test.."));

			PermutationR80();
			OnProgress(std::string("SkeinTest: Passed Skein 80 round permutation variants equivalence test.."));

			TreeParams();
			OnProgress(std::string("SkeinTest: Passed SkeinParams parameter serialization test.."));

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

	void SkeinTest::Exception()
	{
		// test params constructor Skein256
		try
		{
			// invalid fan out -99
			SkeinParams params(32, 32, 99);
			Skein256 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor Skein512
		try
		{
			// invalid fan out -99
			SkeinParams params(64, 64, 99);
			Skein512 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE2"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor Skein1024
		try
		{
			// invalid fan out -99
			SkeinParams params(128, 128, 99);
			Skein1024 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE3"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree Skein256
		try
		{
			Skein256 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE4"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree Skein512
		try
		{
			Skein512 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE5"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree Skein1024
		try
		{
			Skein1024 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE6"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void SkeinTest::Kat(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash1(Digest->DigestSize(), 0);
		std::vector<byte> hash2(Digest->DigestSize(), 0);

		Digest->Update(Input, 0, Input.size());
		Digest->Finalize(hash1, 0);

		if (hash1 != Expected)
		{
			throw TestException(std::string("Kat"), Digest->Name(), std::string("Expected hash is not equal! -SK1"));
		}

		Digest->Compute(Input, hash2);

		if (hash2 != Expected)
		{
			throw TestException(std::string("Kat"), Digest->Name(), std::string("Expected hash is not equal! -SK2"));
		}
	}

	void SkeinTest::Parallel(IDigest* Digest)
	{
		const size_t MINSMP = 2048;
		const size_t MAXSMP = 16384;
		const size_t PRLLEN = Digest->ParallelProfile().ParallelBlockSize();
		const size_t PRLDGR = Digest->ParallelProfile().ParallelMaxDegree();
		std::vector<byte> msg;
		std::vector<byte> code(Digest->DigestSize());
		Prng::SecureRandom rnd;
		bool reduce;

		msg.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			msg.resize(INPLEN);
			IntegerTools::Fill(msg, 0, msg.size(), rnd);
			reduce = Digest->ParallelProfile().ParallelMaxDegree() >= 4;

			try
			{
				while (reduce)
				{
					Digest->Compute(msg, code);
					reduce = Digest->ParallelProfile().ParallelMaxDegree() >= 4;

					if (reduce)
					{
						Digest->ParallelMaxDegree(Digest->ParallelProfile().ParallelMaxDegree() - 2);
					}
				}

				// restore parallel degree and block size
				Digest->ParallelMaxDegree(PRLDGR);
				Digest->ParallelProfile().SetBlockSize(PRLLEN);
			}
			catch (const std::exception&)
			{
				throw TestException(std::string("Parallel"), Digest->Name(), std::string("Parallel integrity test has failed! -BP1"));
			}
		}
	}

	void SkeinTest::PermutationR72()
	{
		std::array<ulong, 4> input{ 0, 1, 2, 3 };
		std::array<ulong, 2> tweak{ 0, 1 };
		std::array<ulong, 4> state1;
		std::array<ulong, 4> state2;

		MemoryTools::Clear(state1, 0, 4 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 4 * sizeof(ulong));

		Skein::PemuteP256C(input, tweak, state1, 72);
		Skein::PemuteR72P256U(input, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR72"), std::string("PemuteP256"), std::string("Permutation output is not equal! -SP1"));
		}
	}

	void SkeinTest::PermutationR80()
	{
		std::array<ulong, 16> input;
		std::array<ulong, 2> tweak;
		std::array<ulong, 16> state1;
		std::array<ulong, 16> state2;
		Prng::SecureRandom rnd;

		IntegerTools::Fill<std::array<ulong, 16>>(input, 0, 16, rnd);
		IntegerTools::Fill<std::array<ulong, 2>>(tweak, 0, 2, rnd);
		MemoryTools::Clear(state1, 0, 16 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 16 * sizeof(ulong));

		Skein::PemuteP1024C(input, tweak, state1, 80);
		Skein::PemuteR80P1024U(input, tweak, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR80"), std::string("PemuteP1024"), std::string("Permutation output is not equal! -SP2"));
		}
	}

	void SkeinTest::Stress(IDigest* Digest)
	{
		const uint MINPRL = static_cast<uint>(Digest->ParallelProfile().ParallelBlockSize());
		const uint MAXPRL = static_cast<uint>(Digest->ParallelProfile().ParallelBlockSize() * 4);

		std::vector<byte> code1(Digest->DigestSize());
		std::vector<byte> code2(Digest->DigestSize());
		std::vector<byte> msg;
		SecureRandom rnd;
		size_t i;

		msg.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			msg.resize(INPLEN);
			IntegerTools::Fill(msg, 0, msg.size(), rnd);

			try
			{
				// simplified access
				Digest->Compute(msg, code1);
				// update/finalize
				Digest->Update(msg, 0, msg.size());
				Digest->Finalize(code2, 0);
			}
			catch (const std::exception&)
			{
				throw TestException(std::string("Stress"), Digest->Name(), std::string("The digest has thrown an exception! -TS1"));
			}

			if (code1 != code2)
			{
				throw TestException(std::string("Stress"), Digest->Name(), std::string("Hash output is not equal! -TS2"));
			}
		}
	}

	void SkeinTest::TreeParams()
	{
		std::vector<byte> code1(8, 7);
		SkeinParams tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		SkeinParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw TestException(std::string("TreeParams"), std::string("SkeinParams"), std::string("Tree parameters test failed! -ST1"));
		}

		std::vector<byte> code2(20, 7);
		SkeinParams tree3(std::vector<byte> { 1, 2, 3, 4 }, 64, 1, 64, 8, 0, code2);
		tres = tree3.ToBytes();
		SkeinParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw TestException(std::string("TreeParams"), std::string("SkeinParams"), std::string("Tree parameters test failed! -ST2"));
		}
	}

	//~~~Private Functions~~~//

	void SkeinTest::Initialize()
	{
		/*lint -save -e146 */
		const std::vector<std::string> message =
		{
			std::string("FF"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
			std::string("FF"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180"),
			std::string("FF"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")
		};
		HexConverter::Decode(message, 9, m_message);

		const std::vector<std::string> expected =
		{
			std::string("0B98DCD198EA0E50A7A244C444E25C23DA30C10FC9A1F270A6637F1F34E67ED2"),
			std::string("8D0FA4EF777FD759DFD4044E6F6A5AC3C774AEC943DCFC07927B723B5DBF408B"),
			std::string("DF28E916630D0B44C4A849DC9A02F07A07CB30F732318256B15D865AC4AE162F"),
			std::string("71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A"),
			std::string("45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B"),
			std::string("91CCA510C263C4DDD010530A33073309628631F308747E1BCBAA90E451CAB92E5188087AF4188773A332303E6667A7A210856F742139000071F48E8BA2A5ADB7"),
			std::string("E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250BCCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8"),
			std::string("1F3E02C46FB80A3FCD2DFBBC7C173800B40C60C2354AF551189EBF433C3D85F9FF1803E6D920493179ED7AE7FCE69C3581A5A2F82D3E0C7A295574D0CD7D217C484D2F6313D59A7718EAD07D0729C24851D7E7D2491B902D489194E6B7D369DB0AB7AA106F0EE0A39A42EFC54F18D93776080985F907574F995EC6A37153A578"),
			std::string("842A53C99C12B0CF80CF69491BE5E2F7515DE8733B6EA9422DFD676665B5FA42FFB3A9C48C217777950848CECDB48F640F81FB92BEF6F88F7A85C1F7CD1446C9161C0AFE8F25AE444F40D3680081C35AA43F640FD5FA3C3C030BCC06ABAC01D098BCC984EBD8322712921E00B1BA07D6D01F26907050255EF2C8E24F716C52A5")
		};
		HexConverter::Decode(expected, 9, m_expected);
		/*lint -restore */
	}

	void SkeinTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
