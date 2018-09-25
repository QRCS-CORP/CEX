#include "SkeinTest.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
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
	using Utility::IntUtils;
	using Utility::MemUtils;
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

	const std::string SkeinTest::DESCRIPTION = "Tests the 256, 512, and 1024 bit versions of Skein.";
	const std::string SkeinTest::FAILURE = "FAILURE! ";
	const std::string SkeinTest::SUCCESS = "SUCCESS! All Skein tests have executed succesfully.";

	SkeinTest::SkeinTest()
		:
		m_progressEvent()
	{
		Initialize();
	}

	SkeinTest::~SkeinTest()
	{
	}

	const std::string SkeinTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SkeinTest::Progress()
	{
		return m_progressEvent;
	}

	std::string SkeinTest::Run()
	{
		try
		{
			EvaluatePermutationSkein256();
			OnProgress(std::string("Passed Skein-256 permutation variants equivalence test.."));

			EvaluatePermutationSkein512();
			OnProgress(std::string("Passed Skein-512 permutation variants equivalence test.."));

			EvaluatePermutationSkein1024();
			OnProgress(std::string("Passed Skein-1024 permutation variants equivalence test.."));

			EvaluateTreeParams();
			OnProgress(std::string("Passed SkeinParams parameter serialization test.."));

			Skein256* sk256 = new Skein256();
			CompareVectorSkein(sk256, m_message256[0], m_expected256[0]);
			CompareVectorSkein(sk256, m_message256[1], m_expected256[1]);
			CompareVectorSkein(sk256, m_message256[2], m_expected256[2]);
			delete sk256;
			OnProgress(std::string("Passed Skein 256 bit digest vector tests.."));

			Skein512* sk512 = new Skein512();
			CompareVectorSkein(sk512, m_message512[0], m_expected512[0]);
			CompareVectorSkein(sk512, m_message512[1], m_expected512[1]);
			CompareVectorSkein(sk512, m_message512[2], m_expected512[2]);
			delete sk512;
			OnProgress(std::string("Passed Skein 512 bit digest vector tests.."));/**/

			Skein1024* sk1024 = new Skein1024();
			CompareVectorSkein(sk1024, m_message1024[0], m_expected1024[0]);
			CompareVectorSkein(sk1024, m_message1024[1], m_expected1024[1]);
			CompareVectorSkein(sk1024, m_message1024[2], m_expected1024[2]);
			delete sk1024;
			OnProgress(std::string("Passed Skein 1024 bit digest vector tests.."));

			Skein256* sks1 = new Skein256(true);
			SkeinParams sp1(32, 32, 8);
			Skein256* sks2 = new Skein256(sp1);
			EvaluateParallelSkein(sks1, sks2);
			delete sks1;
			delete sks2;
			OnProgress(std::string("Passed Skein 256 parallelization tests.."));

			Skein512* skm1 = new Skein512(true);
			SkeinParams sp2(64, 64, 8);
			Skein512* skm2 = new Skein512(sp2);
			EvaluateParallelSkein(skm1, skm2);
			delete skm1;
			delete skm2;
			OnProgress(std::string("Passed Skein 512 parallelization tests.."));

			Skein1024* skl1 = new Skein1024(true);
			SkeinParams sp3(128, 128, 8);
			Skein1024* skl2 = new Skein1024(sp3);
			EvaluateParallelSkein(skl1, skl2);
			delete skl1;
			delete skl2;
			OnProgress(std::string("Passed Skein 1024 parallelization tests.."));

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

	void SkeinTest::CompareVectorSkein(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash1(Digest->DigestSize(), 0);
		std::vector<byte> hash2(Digest->DigestSize(), 0);

		Digest->Update(Input, 0, Input.size());
		Digest->Finalize(hash1, 0);

		if (hash1 != Expected)
		{
			throw TestException("SKein Vector: Expected hash is not equal!");
		}

		Digest->Compute(Input, hash2);

		if (hash2 != Expected)
		{
			throw TestException("SKein Vector: Expected hash is not equal!");
		}
	}

	void SkeinTest::EvaluateParallelSkein(IDigest* Digest1, IDigest* Digest2)
	{
		std::vector<byte> hash1(Digest1->DigestSize(), 0);
		std::vector<byte> hash2(Digest1->DigestSize(), 0);
		const uint PRLBLK = static_cast<uint>(Digest1->ParallelBlockSize());
		const uint PRLMIN = static_cast<uint>(Digest1->ParallelProfile().ParallelMinimumSize());
		CEX::Prng::SecureRandom rnd;

		Digest1->ParallelProfile().ParallelBlockSize() = PRLBLK;
		Digest2->ParallelProfile().ParallelBlockSize() = PRLMIN;

		for (size_t i = 0; i < 100; ++i)
		{
			uint prlSize = rnd.NextUInt32(PRLMIN * 8, PRLMIN * 2);
			prlSize -= (prlSize % PRLMIN);
			std::vector<byte> input(static_cast<size_t>(prlSize));
			rnd.Generate(input);

			// set to parallel, but block will be too small.. processed with secondary parallel loop
			Digest1->Update(input, 0, input.size());
			Digest1->Finalize(hash1, 0);

			// this will run in large-block parallel, processed by primary loop
			Digest2->Update(input, 0, input.size());
			Digest2->Finalize(hash2, 0);

			if (hash1 != hash2)
			{
				throw TestException("SKein Vector: Expected hash is not equal!");
			}

			// test partial block-size and compute method
			input.resize(input.size() + rnd.NextUInt32(200, 1), 0xC7);
			Digest1->Compute(input, hash1);

			Digest2->Update(input, 0, input.size());
			Digest2->Finalize(hash2, 0);

			if (hash1 != hash2)
			{
				throw TestException("SKein Vector: Expected hash is not equal!");
			}
		}
	}

	void SkeinTest::EvaluatePermutationSkein256()
	{
		std::array<ulong, 4> input{ 0, 1, 2, 3 };
		std::array<ulong, 2> tweak{ 0, 1 };
		std::array<ulong, 4> state1;
		std::array<ulong, 4> state2;

		MemUtils::Clear(state1, 0, 4 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 4 * sizeof(ulong));

		Skein::PemuteP256C(input, tweak, state1, 72);
		Skein::PemuteR72P256U(input, tweak, state2);

		if (state1 != state2)
		{
			throw TestException("SKein Permutation: Permutation output is not equal!");
		}
	}

	void SkeinTest::EvaluatePermutationSkein512()
	{
		std::array<ulong, 8> input{ 0, 1, 2, 3, 4, 5, 6, 7 };
		std::array<ulong, 2> tweak{ 0, 1 };
		std::array<ulong, 8> state1;
		std::array<ulong, 8> state2;

		MemUtils::Clear(state1, 0, 8 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 8 * sizeof(ulong));

		Skein::PemuteP512C(input, tweak, state1, 72);
		Skein::PemuteR72P512U(input, tweak, state2);

		if (state1 != state2)
		{
			throw TestException("SKein Permutation: Permutation output is not equal!");
		}

#if defined(__AVX2__)

		std::array<ulong, 8> state3;

		MemUtils::Clear(state3, 0, 8 * sizeof(ulong));
		Skein::PemuteR72P512V(input, tweak, state3);

		if (state1 != state3)
		{
			throw TestException("SKein Permutation: Permutation output is not equal!");
		}
#endif

	}

	void SkeinTest::EvaluatePermutationSkein1024()
	{
		std::array<ulong, 16> input;
		std::array<ulong, 2> tweak;
		std::array<ulong, 16> state1;
		std::array<ulong, 16> state2;
		Prng::SecureRandom rnd;

		IntUtils::Fill(input, 0, 16, rnd);
		IntUtils::Fill(tweak, 0, 2, rnd);
		MemUtils::Clear(state1, 0, 16 * sizeof(ulong));
		MemUtils::Clear(state2, 0, 16 * sizeof(ulong));

		Skein::PemuteP1024C(input, tweak, state1, 80);
		Skein::PemuteR80P1024U(input, tweak, state2);

		if (state1 != state2)
		{
			throw TestException("SKein Permutation: Permutation output is not equal!");
		}
	}

	void SkeinTest::Initialize()
	{
		/*lint -save -e146 */
		const std::vector<std::string> message256 =
		{
			std::string("FF"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0")
		};
		HexConverter::Decode(message256, 3, m_message256);

		const std::vector<std::string> message512 =
		{
			std::string("FF"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180")
		};
		HexConverter::Decode(message512, 3, m_message512);

		const std::vector<std::string> message1024 =
		{
			std::string("FF"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180"),
			std::string("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A09080706050403020100")
		};
		HexConverter::Decode(message1024, 3, m_message1024);

		const std::vector<std::string> expected256 =
		{
			std::string("0B98DCD198EA0E50A7A244C444E25C23DA30C10FC9A1F270A6637F1F34E67ED2"),
			std::string("8D0FA4EF777FD759DFD4044E6F6A5AC3C774AEC943DCFC07927B723B5DBF408B"),
			std::string("DF28E916630D0B44C4A849DC9A02F07A07CB30F732318256B15D865AC4AE162F")
		};
		HexConverter::Decode(expected256, 3, m_expected256);

		const std::vector<std::string> expected512 =
		{
			std::string("71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8CA698D864307ED3E80B6EF1570812AC5272DC409B5A012DF2A579102F340617A"),
			std::string("45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B"),
			std::string("91CCA510C263C4DDD010530A33073309628631F308747E1BCBAA90E451CAB92E5188087AF4188773A332303E6667A7A210856F742139000071F48E8BA2A5ADB7")
		};
		HexConverter::Decode(expected512, 3, m_expected512);

		const std::vector<std::string> expected1024 =
		{
			std::string("E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250BCCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8"),
			std::string("1F3E02C46FB80A3FCD2DFBBC7C173800B40C60C2354AF551189EBF433C3D85F9FF1803E6D920493179ED7AE7FCE69C3581A5A2F82D3E0C7A295574D0CD7D217C484D2F6313D59A7718EAD07D0729C24851D7E7D2491B902D489194E6B7D369DB0AB7AA106F0EE0A39A42EFC54F18D93776080985F907574F995EC6A37153A578"),
			std::string("842A53C99C12B0CF80CF69491BE5E2F7515DE8733B6EA9422DFD676665B5FA42FFB3A9C48C217777950848CECDB48F640F81FB92BEF6F88F7A85C1F7CD1446C9161C0AFE8F25AE444F40D3680081C35AA43F640FD5FA3C3C030BCC06ABAC01D098BCC984EBD8322712921E00B1BA07D6D01F26907050255EF2C8E24F716C52A5")
		};
		HexConverter::Decode(expected1024, 3, m_expected1024);
		/*lint -restore */
	}

	void SkeinTest::EvaluateTreeParams()
	{
		std::vector<byte> code1(8, 7);

		SkeinParams tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		SkeinParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw std::string("SkeinTest: Tree parameters test failed!");
		}

		std::vector<byte> code2(20, 7);
		SkeinParams tree3(std::vector<byte> { 1, 2, 3, 4 }, 64, 1, 64, 8, 0, code2);
		tres = tree3.ToBytes();
		SkeinParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw std::string("SkeinTest: Tree parameters test failed!");
		}
	}

	void SkeinTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
