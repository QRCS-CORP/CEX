#include "SHA3Test.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Keccak.h"
#include "../CEX/SHA3256.h"
#include "../CEX/SHA3512.h"
#include "../CEX/SHA31024.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#elif defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif

namespace Test
{
	using Exception::CryptoDigestException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Prng::SecureRandom;
	using Cipher::SymmetricKey;
	using namespace Digest;
#if defined(__AVX512__)
	using Numeric::ULong512;
#elif defined(__AVX2__)
	using Numeric::ULong256;
#endif

	const std::string SHA3Test::CLASSNAME = "SHA3Test";
	const std::string SHA3Test::DESCRIPTION = "SHA-3 Vector KATs; tests the 256, 512, and 1024 versions of Keccak.";
	const std::string SHA3Test::SUCCESS = "SUCCESS! All Keccak tests have executed succesfully.";

	//~~~Constructor~~~//

	SHA3Test::SHA3Test()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	SHA3Test::~SHA3Test()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_message);
	}

	//~~~Accessors~~~//

	const std::string SHA3Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &SHA3Test::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string SHA3Test::Run()
	{
		try
		{
			Ancillary();
			OnProgress(std::string("SHA3Test: Passed SHA3 component functions tests.."));

			Exception();
			OnProgress(std::string("SHA3Test: Passed SHA3-256/512/1024 exception handling tests.."));

			PermutationR24();
			OnProgress(std::string("SHA3Test: Passed Keccak 24-round permutation variants equivalence test.."));
			PermutationR48();
			OnProgress(std::string("SHA3Test: Passed Keccak 48-round permutation variants equivalence test.."));

			SHA3256* dgt256s = new SHA3256(false);
			Kat(dgt256s, m_message[0], m_expected[0]);
			Kat(dgt256s, m_message[1], m_expected[1]);
			Kat(dgt256s, m_message[2], m_expected[2]);
			Kat(dgt256s, m_message[3], m_expected[3]);
			OnProgress(std::string("SHA3Test: Passed SHA3-256 bit digest vector tests.."));

			SHA3512* dgt512s = new SHA3512(false);
			Kat(dgt512s, m_message[0], m_expected[4]);
			Kat(dgt512s, m_message[1], m_expected[5]);
			Kat(dgt512s, m_message[2], m_expected[6]);
			Kat(dgt512s, m_message[3], m_expected[7]);
			OnProgress(std::string("SHA3Test: Passed SHA3-512 bit digest vector tests.."));

			SHA31024* dgt1024s = new SHA31024(false);
			Kat(dgt1024s, m_message[0], m_expected[8]);
			Kat(dgt1024s, m_message[1], m_expected[9]);
			Kat(dgt1024s, m_message[2], m_expected[10]);
			Kat(dgt1024s, m_message[3], m_expected[11]);
			OnProgress(std::string("SHA3Test: Passed Keccak-1024 bit digest vector tests.."));

			Stress(dgt256s);
			OnProgress(std::string("SHA3Test: Passed SHA3-256 sequential stress tests.."));

			Stress(dgt512s);
			OnProgress(std::string("SHA3Test: Passed SHA3-512 sequential stress tests.."));

			Stress(dgt1024s);
			OnProgress(std::string("SHA3Test: Passed Keccak-1024 sequential stress tests.."));

			delete dgt256s;
			delete dgt512s;
			delete dgt1024s;

			SHA3256* dgt256p = new SHA3256(true);
			Stress(dgt256p);
			OnProgress(std::string("SHA3Test: Passed SHA3-256 parallel stress tests.."));

			SHA3512* dgt512p = new SHA3512(true);
			Stress(dgt512p);
			OnProgress(std::string("SHA3Test: Passed SHA3-512 parallel stress tests.."));

			SHA31024* dgt1024p = new SHA31024(true);
			Stress(dgt1024p);
			OnProgress(std::string("SHA3Test: Passed Keccak-1024 parallel stress tests.."));

			Parallel(dgt256p);
			OnProgress(std::string("SHA3Test: Passed SHA3-256 parallel tests.."));

			Parallel(dgt512p);
			OnProgress(std::string("SHA3Test: Passed SHA3-512 parallel tests.."));

			Parallel(dgt1024p);
			OnProgress(std::string("SHA3Test: Passed Keccak-1024 parallel tests.."));

			delete dgt256p;
			delete dgt512p;
			delete dgt1024p;

			TreeParams();
			OnProgress(std::string("SHA3Test: Passed KeccakParams parameter serialization test.."));

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

	void SHA3Test::Ancillary()
	{
		std::array<ulong, 25> state = { 0 };
		std::vector<byte> otp(0);

		// SHA3-256
		MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));
		otp.resize(Keccak::KECCAK256_RATE_SIZE);
		Keccak::AbsorbR24(m_message[3], 0, m_message[3].size(), Keccak::KECCAK256_RATE_SIZE, Keccak::KECCAK_SHA3_DOMAIN, state);
		Keccak::SqueezeR24(state, otp, 0, 1, Keccak::KECCAK256_RATE_SIZE);

		if (IntegerTools::Compare(m_expected[3], 0, otp, 0, Keccak::KECCAK256_DIGEST_SIZE) == false)
		{
			throw TestException(std::string("Exception"), std::string("SHA3-256"), std::string("Exception handling failure! -SA2"));
		}

		// SHA3-512
		MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));
		MemoryTools::Clear(otp, 0, otp.size());
		otp.resize(Keccak::KECCAK512_RATE_SIZE);
		Keccak::AbsorbR24(m_message[3], 0, m_message[3].size(), Keccak::KECCAK512_RATE_SIZE, Keccak::KECCAK_SHA3_DOMAIN, state);
		Keccak::SqueezeR24(state, otp, 0, 1, Keccak::KECCAK512_RATE_SIZE);

		if (IntegerTools::Compare(m_expected[7], 0, otp, 0, Keccak::KECCAK512_DIGEST_SIZE) == false)
		{
			throw TestException(std::string("Exception"), std::string("SHA3-512"), std::string("Exception handling failure! -SA3"));
		}

		// SHA3-1024
		MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));
		MemoryTools::Clear(otp, 0, otp.size());
		otp.resize(Keccak::KECCAK1024_RATE_SIZE * 4);
		Keccak::AbsorbR48(m_message[3], 0, m_message[3].size(), Keccak::KECCAK1024_RATE_SIZE, Keccak::KECCAK_SHA3_DOMAIN, state);
		Keccak::SqueezeR48(state, otp, 0, 4, Keccak::KECCAK1024_RATE_SIZE);

		if (IntegerTools::Compare(m_expected[11], 0, otp, 0, Keccak::KECCAK1024_DIGEST_SIZE) == false)
		{
			throw TestException(std::string("Exception"), std::string("SHA3-1024"), std::string("Exception handling failure! -SA4"));
		}
	}

	void SHA3Test::Exception()
	{
		// test params constructor SHA3256
		try
		{
			// invalid fan out -99
			KeccakParams params(32, 32, 99);
			SHA3256 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE1"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor SHA3512
		try
		{
			// invalid fan out -99
			KeccakParams params(64, 64, 99);
			SHA3512 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE2"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor SHA31024
		try
		{
			// invalid fan out -99
			KeccakParams params(128, 128, 99);
			SHA31024 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE3"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree SHA3256
		try
		{
			SHA3256 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE4"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree SHA3512
		try
		{
			SHA3512 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE5"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree SHA31024
		try
		{
			SHA31024 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE6"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void SHA3Test::Kat(IDigest* Digest, std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> otp(Digest->DigestSize());

		Digest->Update(Message, 0, Message.size());
		Digest->Finalize(otp, 0);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat1024"), Digest->Name(), std::string("Expected hash is not equal! -KK1"));
		}
	}

	void SHA3Test::Parallel(IDigest* Digest)
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
		reduce = Digest->ParallelProfile().ParallelMaxDegree() >= 4;

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t INPLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			msg.resize(INPLEN);
			rnd.Generate(msg, 0, msg.size());
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
			catch (std::exception const&)
			{
				throw TestException(std::string("Parallel"), Digest->Name(), std::string("Parallel integrity test has failed! -BP1"));
			}
		}
	}

	void SHA3Test::PermutationR24()
	{
		std::array<ulong, 25> state1;
		std::array<ulong, 25> state2;

		MemoryTools::Clear(state1, 0, 25 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 25 * sizeof(ulong));

		Keccak::PermuteR24P1600U(state1);
		Keccak::PermuteR24P1600C(state2);

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR24"), std::string("PermuteR24P1600"), std::string("Permutation output is not equal!"));
		}

#if defined(__AVX2__)

		std::vector<ULong256> state256(25, ULong256(0));

		Keccak::PermuteR24P4x1600H(state256);

		std::vector<ulong> state256ull(100);
		std::memcpy(state256ull.data(), state256.data(), 100 * sizeof(ulong));

		for (size_t i = 0; i < 25; ++i)
		{
			if (state256ull[i] != state1[i / 4])
			{
				throw TestException(std::string("PermutationR24"), std::string("PermuteR24P4x1600H"), std::string("Permutation output is not equal!"));
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<ULong512> state512(25, ULong512(0));

		Keccak::PermuteR24P8x1600H(state512);

		std::vector<ulong> state512ull(100);
		std::memcpy(state512ull.data(), state512.data(), 200 * sizeof(ulong));

		for (size_t i = 0; i < 25; ++i)
		{
			if (state512ull[i] != state1[i / 8])
			{
				throw TestException(std::string("PermutationR24"), std::string("PermuteR24P8x1600H"), std::string("Permutation output is not equal!"));
			}
		}

#endif
	}

	void SHA3Test::PermutationR48()
	{
		std::array<ulong, 25> state1;
		std::array<ulong, 25> state2;

		MemoryTools::Clear(state1, 0, 25 * sizeof(ulong));
		MemoryTools::Clear(state2, 0, 25 * sizeof(ulong));

		Keccak::PermuteR48P1600U(state1);
		Keccak::PermuteR48P1600C(state2);

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR48"), std::string("PermuteR48P1600"), std::string("Permutation output is not equal!"));
		}

#if defined(__AVX2__)

		std::vector<ULong256> state256(25, ULong256(0));

		Keccak::PermuteR48P4x1600H(state256);

		std::vector<ulong> state256ull(100);
		MemoryTools::Copy(state256, 0, state256ull, 0, 100 * sizeof(ulong));

		for (size_t i = 0; i < 25; ++i)
		{
			if (state256ull[i] != state1[i / 4])
			{
				throw TestException(std::string("PermutationR48"), std::string("PermuteR48P4x1600H"), std::string("Permutation output is not equal!"));
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<ULong512> state512(25, ULong512(0));

		Keccak::PermuteR48P8x1600H(state512);

		std::vector<ulong> state512ull(100);
		MemoryTools::Copy(state512, 0, state512ull, 0, 200 * sizeof(ulong));

		for (size_t i = 0; i < 25; ++i)
		{
			if (state512ull[i] != state1[i / 8])
			{
				throw TestException(std::string("PermutationR48"), std::string("PermuteR48P8x1600H"), std::string("Permutation output is not equal!"));
			}
		}

#endif
	}

	void SHA3Test::Stress(IDigest* Digest)
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
			catch (std::exception const&)
			{
				throw TestException(std::string("Stress"), Digest->Name(), std::string("The digest has thrown an exception! -KS1"));
			}

			if (code1 != code2)
			{
				throw TestException(std::string("Stress"), Digest->Name(), std::string("Hash output is not equal! -KS2"));
			}
		}
	}

	void SHA3Test::TreeParams()
	{
		std::vector<byte> code1(8, 7);

		KeccakParams tree1(32, 32, 8);
		tree1.DistributionCode() = code1;
		std::vector<byte> tres = tree1.ToBytes();
		KeccakParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw TestException(std::string("TreeParams"), std::string("KeccakParams"), std::string("Tree parameters test failed! -KT1"));
		}

		std::vector<byte> code2(20, 7);
		KeccakParams tree3(0, 64, 1, 128, 8, 1, code2);
		tres = tree3.ToBytes();
		KeccakParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw TestException(std::string("TreeParams"), std::string("KeccakParams"), std::string("Tree parameters test failed! -KT2"));
		}
	}

	//~~~Private Functions~~~//

	void SHA3Test::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> expected =
		{
			std::string("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"),
			std::string("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532"),
			std::string("41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376"),
			std::string("79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787"),
			std::string("A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A615B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26"),
			std::string("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0"),
			std::string("04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636DEE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E"),
			std::string("E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA81B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00"),
			std::string("93C02A730E8D79D04673B0501C1B98D1F02EE75AF0C82B2FD29CB1FFF5A442D5D107E7D624F0CE282205DECE32F61ACE8A2EE68F301D0D21439FED48328E9B98"
				"892449AD5EA9B4606C65180D0EA57A1B4078AA64479AA9E620CDEAD6F40391632E502AB4A06FF39A867515F6B3DDDA51D6A2DFFC62820FEBE3C6C9491BA1FE81"),
			std::string("7ABA011E268A377C7DE97D19EF3D9ED5D3D483148D998E03AFC114B14C46A6F3867197BCBE92F94657601867476715C7AC933190AE906E8352442ED2F8E3D8E2"
				"316713B2E4B3AD90EE4E94D03F5C20687AB718767B87610703AA664AC787802FC3F978EF179EDAA6DFA60235494C59180BB56FDC7AACC0DB094FB646E6D0BFDD"),
			std::string("4887B715872192C205538157F07A9DE7FC4D46105D2B79BB3445367DCAF85E634E4A5E81B1EF9C8440CF1CB532DB280FFE0C7497EB658260B0C98A7CF55F2560"
				"C24E79AC0518B8AC4BF4E13752BDD3314960F6506311AC15531DCF76D974F92262FD3EB08B37C9D6D5251770BFA1CC20C2231B368F0680F94AB367681D9B8B75"),
			std::string("335B34D5CFE46864FC216173B4F4F77A229483B85CB1E02EC3CF7375FD2255E00D4E184D0421A6046E876AFE5A8F281A265653E51A1BD3DEEA65D7E8EBED8F0B"
				"AD83ECC750CFD0BE3F41D4EC1F96BAAD0A785136209EB49E0EF776FECEC4CB6EB80A371D00F9339BD2D933715127E18271D9650E4BEF697AB1AF78ECA7B7A29C")
		};
		HexConverter::Decode(expected, 12, m_expected);

		const std::vector<std::string> message =
		{
			std::string(""),
			std::string("616263"),
			std::string("6162636462636465636465666465666765666768666768696768696A68696A6B696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071"),
			std::string("A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
				"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
				"A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3")
		};
		HexConverter::Decode(message, 4, m_message);
		/*lint -restore */
	}

	void SHA3Test::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
