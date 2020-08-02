#include "SHA2Test.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SHA2.h"
#include "../CEX/SHA2256.h"
#include "../CEX/SHA2512.h"

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
	using Exception::CryptoDigestException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Prng::SecureRandom;
#if defined(__AVX2__)
	using Numeric::UInt256;
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::UInt512;
	using Numeric::ULong512;
#endif
	using Digest::SHA2;
	using Digest::SHA2256;
	using Digest::SHA2512; 
	using Digest::SHA2Params;

	const std::string SHA2Test::CLASSNAME = "SHA2Test";
	const std::string SHA2Test::DESCRIPTION = "Tests SHA-2 256/512 with NIST KAT vectors.";
	const std::string SHA2Test::SUCCESS = "SUCCESS! All SHA-2 tests have executed succesfully.";

	//~~~Constructor~~~//

	SHA2Test::SHA2Test()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	SHA2Test::~SHA2Test()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_message);
	}

	//~~~Accessors~~~//

	const std::string SHA2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SHA2Test::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string SHA2Test::Run()
	{
		try
		{
			Ancillary();
			OnProgress(std::string("SHA2Test: Passed SHA2-256/512 compact functions tests.."));

			Exception();
			OnProgress(std::string("SHA2Test: Passed SHA2-256/512 exception handling tests.."));

			SHA2256* dgt256s = new SHA2256(false);
			SHA2512* dgt512s = new SHA2512(false);

			Kat(dgt256s, m_message[0], m_expected[0]);
			Kat(dgt256s, m_message[1], m_expected[1]);
			Kat(dgt256s, m_message[2], m_expected[2]);
			Kat(dgt256s, m_message[3], m_expected[3]);
			OnProgress(std::string("SHA2Test: Passed sequential SHA-256 bit digest vector tests.."));

			Kat(dgt512s, m_message[0], m_expected[4]);
			Kat(dgt512s, m_message[1], m_expected[5]);
			Kat(dgt512s, m_message[2], m_expected[6]);
			Kat(dgt512s, m_message[3], m_expected[7]);
			OnProgress(std::string("SHA2Test: Passed sequential SHA-512 bit digest vector tests.."));

			Stress(dgt256s);
			OnProgress(std::string("SHA2Test: Passed SHA-256 sequential stress tests.."));

			Stress(dgt512s);
			OnProgress(std::string("SHA2Test: Passed SHA-512 sequential stress tests.."));

			delete dgt256s;
			delete dgt512s;

			SHA2256* dgt256p = new SHA2256(true);
			SHA2512* dgt512p = new SHA2512(true);

			Parallel(dgt256p);
			OnProgress(std::string("SHA2Test: Passed SHA-256 parallel integrity tests.."));
			
			Parallel(dgt512p);
			OnProgress(std::string("SHA2Test: Passed SHA-512 parallel integrity tests.."));

			delete dgt256p;
			delete dgt512p;

			PermutationR64();
			OnProgress(std::string("SHA2Test: Passed Sha2-256 permutation variants equivalence test.."));
			PermutationR80();
			OnProgress(std::string("SHA2Test: Passed Sha2-512 permutation variants equivalence test.."));

			TreeParams();
			OnProgress(std::string("SHA2Test: Passed SHA2Params parameter serialization test.."));

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

	void SHA2Test::Ancillary()
	{
		std::vector<byte> otp(0);

		// SHA2-256

		otp.resize(m_expected[0].size());
		SHA2::Compute256(m_message[0], 0, m_message[0].size(), otp, 0);

		if (otp != m_expected[0])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute256"), std::string("Expected values don't match! -SA1"));
		}

		otp.resize(m_expected[1].size());
		SHA2::Compute256(m_message[1], 0, m_message[1].size(), otp, 0);

		if (otp != m_expected[1])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute256"), std::string("Expected values don't match! -SA2"));
		}

		otp.resize(m_expected[2].size());
		SHA2::Compute256(m_message[2], 0, m_message[2].size(), otp, 0);

		if (otp != m_expected[2])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute256"), std::string("Expected values don't match! -SA3"));
		}

		otp.resize(m_expected[3].size());
		SHA2::Compute256(m_message[3], 0, m_message[3].size(), otp, 0);

		if (otp != m_expected[3])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute256"), std::string("Expected values don't match! -SA4"));
		}

		// SHA2-384

		otp.resize(m_expected[8].size());
		SHA2::Compute384(m_message[0], 0, m_message[0].size(), otp, 0);

		if (otp != m_expected[8])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute384"), std::string("Expected values don't match! -SA5"));
		}

		otp.resize(m_expected[9].size());
		SHA2::Compute384(m_message[1], 0, m_message[1].size(), otp, 0);

		if (otp != m_expected[9])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute384"), std::string("Expected values don't match! -SA6"));
		}

		otp.resize(m_expected[10].size());
		SHA2::Compute384(m_message[2], 0, m_message[2].size(), otp, 0);

		if (otp != m_expected[10])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute384"), std::string("Expected values don't match! -SA7"));
		}

		otp.resize(m_expected[11].size());
		SHA2::Compute384(m_message[3], 0, m_message[3].size(), otp, 0);

		if (otp != m_expected[11])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute384"), std::string("Expected values don't match! -SA8"));
		}

		// SHA2-512

		otp.resize(m_expected[4].size());
		SHA2::Compute512(m_message[0], 0, m_message[0].size(), otp, 0);

		if (otp != m_expected[4])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute512"), std::string("Expected values don't match! -SA9"));
		}

		otp.resize(m_expected[5].size());
		SHA2::Compute512(m_message[1], 0, m_message[1].size(), otp, 0);

		if (otp != m_expected[5])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute512"), std::string("Expected values don't match! -SA10"));
		}

		otp.resize(m_expected[6].size());
		SHA2::Compute512(m_message[2], 0, m_message[2].size(), otp, 0);

		if (otp != m_expected[6])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute512"), std::string("Expected values don't match! -SA11"));
		}

		otp.resize(m_expected[7].size());
		SHA2::Compute512(m_message[3], 0, m_message[3].size(), otp, 0);

		if (otp != m_expected[7])
		{
			throw TestException(std::string("Ancillary"), std::string("Compute512"), std::string("Expected values don't match! -SA12"));
		}
	}

	void SHA2Test::Exception()
	{
		// test params constructor SHA2256
		try
		{
			// invalid fan out -99
			SHA2Params params(32, 32, 99);
			SHA2256 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE1"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor SHA2512
		try
		{
			// invalid fan out -99
			SHA2Params params(64, 64, 99);
			SHA2512 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE2"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree SHA2256
		try
		{
			SHA2256 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -SE3"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree SHA2512
		try
		{
			SHA2512 dgt;
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
	}

	void SHA2Test::Kat(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected)
	{
		std::vector<byte> code(Digest->DigestSize(), 0);

		Digest->Update(Input, 0, Input.size());
		Digest->Finalize(code, 0);

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), Digest->Name(), std::string("Expected hash is not equal!"));
		}

		code.clear();
		code.resize(Digest->DigestSize());
		Digest->Compute(Input, code);

		if (Expected != code)
		{
			throw TestException(std::string("Kat"), Digest->Name(), std::string("Expected hash is not equal!"));
		}
	}

	void SHA2Test::Parallel(IDigest* Digest)
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
			rnd.Generate(msg, 0, msg.size());

			try
			{
				reduce = Digest->ParallelProfile().ParallelMaxDegree() >= 4;

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

	void SHA2Test::PermutationR64()
	{
		std::vector<byte> input(64, 128U);
		std::array<uint, 8> state1;
		std::array<uint, 8> state2;

		MemoryTools::Clear(state1, 0, 8 * sizeof(uint));
		MemoryTools::Clear(state2, 0, 8 * sizeof(uint));

		SHA2::PermuteR64P512C(input, 0, state1);
		SHA2::PermuteR64P512U(input, 0, state2);

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR64"), std::string("PermuteR64P512"), std::string("Permutation output is not equal!"));
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128U);
		std::vector<UInt256> state256(8, UInt256(0));

		SHA2::PermuteR64P8x512H(input256, 0, state256);

		std::vector<uint> state256ul(32);
		std::memcpy(state256ul.data(), state256.data(), 32 * sizeof(uint));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ul[i] != state1[i / 8])
			{
				throw TestException(std::string("PermutationR64"), std::string("PermuteR64P8x512H"), std::string("Permutation output is not equal!"));
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<UInt512> state512(8, UInt512(0));

		SHA2::PermuteR64P16x512H(input512, 0, state512);

		std::vector<uint> state512ul(64);
		std::memcpy(state512ul.data(), state512.data(), 64 * sizeof(uint));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ul[i] != state1[i / 16])
			{
				throw TestException(std::string("PermutationR64"), std::string("PermuteR64P16x512H"), std::string("Permutation output is not equal!"));
			}
		}

#endif
	}

	void SHA2Test::PermutationR80()
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
			throw TestException(std::string("PermutationR80"), std::string("PermuteR80P1024"), std::string("Permutation output is not equal! -SP1"));
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128U);
		std::vector<ULong256> state256(8, ULong256(0));

		SHA2::PermuteR80P4x1024H(input256, 0, state256);

		std::vector<ulong> state256ull(32);
		MemoryTools::Copy(state256, 0, state256ull, 0, 32 * sizeof(ulong));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ull[i] != state1[i / 4])
			{
				throw TestException(std::string("PermutationR80"), std::string("PermuteR80P4x1024H"), std::string("Permutation output is not equal! -SP2"));
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<ULong512> state512(8, ULong512(0));

		SHA2::PermuteR80P8x1024H(input512, 0, state512);

		std::vector<ulong> state512ull(64);
		MemoryTools::Copy(state512, 0, state512ull, 0, 64 * sizeof(ulong));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ull[i] != state1[i / 8])
			{
				throw TestException(std::string("PermutationR80"), std::string("PermuteR80P8x1024H"), std::string("Permutation output is not equal! -SP3"));
			}
		}

#endif
	}

	void SHA2Test::Stress(IDigest* Digest)
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
			rnd.Generate(msg, 0, msg.size());

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
				throw TestException(std::string("Stress"), Digest->Name(), std::string("The digest has thrown an exception! -SS1"));
			}

			if (code1 != code2)
			{
				throw TestException(std::string("Stress"), Digest->Name(), std::string("Hash output is not equal! -SS2"));
			}
		}
	}

	void SHA2Test::TreeParams()
	{
		std::vector<byte> code1(8, 7);

		SHA2Params tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		SHA2Params tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw TestException(std::string("TreeParams"), std::string("SHA2Params"), std::string("Tree parameters test failed! -ST1"));
		}

		std::vector<byte> code2(20, 7);
		SHA2Params tree3(0, 64, 1, 128, 8, 1, code2);
		tres = tree3.ToBytes();
		SHA2Params tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw TestException(std::string("TreeParams"), std::string("SHA2Params"), "Tree parameters test failed! -ST2");
		}
	}

	//~~~Private Functions~~~//

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

		const std::vector<std::string> expected =
		{
			std::string("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
			std::string("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"),
			std::string("248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"),
			std::string("CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1"),
			std::string("DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F"),
			std::string("CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E"),
			std::string("204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C33596FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445"),
			std::string("8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909"),
			std::string("CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"),
			std::string("38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"),
			std::string("3391FDDDFC8DC7393707A65B1B4709397CF8B1D162AF05ABFE8F450DE5F36BC6B0455A8520BC4E6F5FE95B1FE3C8452B"),
			std::string("09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039")
		};
		HexConverter::Decode(expected, 12, m_expected);

		/*lint -restore */
	}

	void SHA2Test::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
