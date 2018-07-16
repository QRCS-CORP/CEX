#include "SHA2Test.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
#include "../CEX/SHA2.h"
#include "../CEX/SHA256.h"
#include "../CEX/SHA512.h"

#if defined(__AVX2__)
#	include "../CEX/UInt256.h"
#	include "../CEX/ULong256.h"
#endif

#if defined(__AVX512__)
#	include "../CEX/UInt512.h"
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using namespace Digest;
	using Utility::MemUtils;

#if defined(__AVX2__)
	using Numeric::UInt256;
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::UInt512;
	using Numeric::ULong512;
#endif

	const std::string SHA2Test::DESCRIPTION = "Tests SHA-2 256/512 with NIST KAT vectors.";
	const std::string SHA2Test::FAILURE = "FAILURE! ";
	const std::string SHA2Test::SUCCESS = "SUCCESS! All SHA-2 tests have executed succesfully.";

	SHA2Test::SHA2Test()
		:
		m_progressEvent()
	{
		Initialize();
	}

	SHA2Test::~SHA2Test()
	{
	}

	const std::string SHA2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SHA2Test::Progress()
	{
		return m_progressEvent;
	}

	std::string SHA2Test::Run()
	{
		try
		{
			ComparePermutation256();
			OnProgress(std::string("Passed Sha2-256 permutation variants equivalence test.."));
			ComparePermutation512();
			OnProgress(std::string("Passed Sha2-512 permutation variants equivalence test.."));

			TreeParamsTest();
			OnProgress(std::string("Passed SHA2Params parameter serialization test.."));

			SHA256* sha256 = new SHA256();
			CompareOutput(sha256, m_message[0], m_exp256[0]);
			CompareOutput(sha256, m_message[1], m_exp256[1]);
			CompareOutput(sha256, m_message[2], m_exp256[2]);
			CompareOutput(sha256, m_message[3], m_exp256[3]);
			delete sha256;
			OnProgress(std::string("Sha2Test: Passed SHA-2 256 bit digest vector tests.."));/**/

			SHA512* sha512 = new SHA512();
			CompareOutput(sha512, m_message[0], m_exp512[0]);
			CompareOutput(sha512, m_message[1], m_exp512[1]);
			CompareOutput(sha512, m_message[2], m_exp512[2]);
			CompareOutput(sha512, m_message[3], m_exp512[3]);
			delete sha512;
			OnProgress(std::string("Sha2Test: Passed SHA-2 512 bit digest vector tests.."));

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

	void SHA2Test::CompareOutput(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> hash(Digest->DigestSize(), 0);

		Digest->Update(Input, 0, Input.size());
		Digest->Finalize(hash, 0);

		if (Expected != hash)
		{
			throw TestException("SHA2: Expected hash is not equal!");
		}

		hash.clear();
		hash.resize(Digest->DigestSize());
		Digest->Compute(Input, hash);

		if (Expected != hash)
		{
			throw TestException("SHA2: Expected hash is not equal!");
		}
	}

	void SHA2Test::ComparePermutation256()
	{
		std::vector<byte> input(64, 128U);
		std::array<uint, 8> state1;
		std::array<uint, 8> state2;

		MemUtils::Clear(state1, 0, 8 * sizeof(uint));
		MemUtils::Clear(state2, 0, 8 * sizeof(uint));

		SHA2::PermuteR64P512C(input, 0, state1);
		SHA2::PermuteR64P512U(input, 0, state2);

		if (state1 != state2)
		{
			throw TestException("Sha2 Permutation: Permutation output is not equal!");
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128U);
		std::vector<UInt256> state256(8, UInt256(0));

		SHA2::PermuteR64P4096H(input256, 0, state256);

		std::vector<uint> state256ul(32);
		MemUtils::Copy(state256, 0, state256ul, 0, 32 * sizeof(uint));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ul[i] != state1[i / 8])
			{
				throw TestException("Sha2 Permutation: Permutation output is not equal!");
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<UInt512> state512(8, UInt512(0));

		SHA2::PermuteR64P8192H(input512, 0, state512);

		std::vector<uint> state512ul(64);
		MemUtils::Copy(state512, 0, state512ul, 0, 64 * sizeof(uint));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ul[i] != state1[i / 16])
			{
				throw TestException("Sha2 Permutation: Permutation output is not equal!");
			}
		}

#endif
	}

	void SHA2Test::ComparePermutation512()
	{
		std::vector<byte> input(128, 128U);
		std::array<ulong, 8> state1;
		std::array<ulong, 8> state2;

		std::memset(state1.data(), 0, 8 * sizeof(ulong));
		std::memset(state2.data(), 0, 8 * sizeof(ulong));

		SHA2::PermuteR80P1024C(input, 0, state1);
		SHA2::PermuteR80P1024U(input, 0, state2);

		if (state1 != state2)
		{
			throw TestException("Sha2 Permutation: Permutation output is not equal!");
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128U);
		std::vector<ULong256> state256(8, ULong256(0));

		SHA2::PermuteR80P4096H(input256, 0, state256);

		std::vector<ulong> state256ull(32);
		MemUtils::Copy(state256, 0, state256ull, 0, 32 * sizeof(ulong));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ull[i] != state1[i / 4])
			{
				throw TestException("Sha2 Permutation: Permutation output is not equal!");
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<ULong512> state512(8, ULong512(0));

		SHA2::PermuteR80P8192H(input512, 0, state512);

		std::vector<ulong> state512ull(64);
		MemUtils::Copy(state512, 0, state512ull, 0, 64 * sizeof(ulong));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ull[i] != state1[i / 8])
			{
				throw TestException("Sha2 Permutation: Permutation output is not equal!");
			}
		}

#endif
	}

	void SHA2Test::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> message =
		{
			std::string("616263"),
			std::string(""),
			std::string("6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"),
			std::string("61626364656667686263646566676869636465666768696A6465666768696A6B65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F707172736D6E6F70717273746E6F707172737475")
		};
		HexConverter::Decode(message, 4, m_message);

		const std::vector<std::string> exp256 =
		{
			std::string("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
			std::string("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
			std::string("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"),
			std::string("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1")
		};
		HexConverter::Decode(exp256, 4, m_exp256);

		const std::vector<std::string> exp512 =
		{
			std::string("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"),
			std::string("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"),
			std::string("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C33596FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445"),
			std::string("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909")
		};
		HexConverter::Decode(exp512, 4, m_exp512);
		/*lint -restore */
	}

	void SHA2Test::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}

	void SHA2Test::TreeParamsTest()
	{
		std::vector<byte> code1(8, 7);

		SHA2Params tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		SHA2Params tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw std::string("SHA2Test: Tree parameters test failed!");
		}

		std::vector<byte> code2(20, 7);
		SHA2Params tree3(0, 64, 1, 128, 8, 1, code2);
		tres = tree3.ToBytes();
		SHA2Params tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw std::string("SHA2Test: Tree parameters test failed!");
		}
	}
}
