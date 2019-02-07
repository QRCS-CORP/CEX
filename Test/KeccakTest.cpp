#include "KeccakTest.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/Keccak.h"
#include "../CEX/Keccak256.h"
#include "../CEX/Keccak512.h"
#include "../CEX/Keccak1024.h"
#include "../CEX/MemoryTools.h"
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
	using Cipher::SymmetricKey;
	using namespace Digest;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string KeccakTest::CLASSNAME = "KeccakTest";
	const std::string KeccakTest::DESCRIPTION = "SHA-3 Vector KATs; tests the 256, 512, and 1024 versions of Keccak.";
	const std::string KeccakTest::SUCCESS = "SUCCESS! All Keccak tests have executed succesfully.";

	//~~~Constructor~~~//

	KeccakTest::KeccakTest()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
		Initialize();
	}

	KeccakTest::~KeccakTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_message);
	}

	//~~~Accessors~~~//

	const std::string KeccakTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &KeccakTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string KeccakTest::Run()
	{
		try
		{
			CpuDetect detect;

			Exception();
			OnProgress(std::string("KeccakTest: Passed Keccak-256/512/1024 exception handling tests.."));

			PermutationR24();
			OnProgress(std::string("KeccakTest: Passed Keccak 24-round permutation variants equivalence test.."));
			PermutationR48();
			OnProgress(std::string("KeccakTest: Passed Keccak 48-round permutation variants equivalence test.."));

			Kat256(m_message[0], m_expected[0]);
			Kat256(m_message[1], m_expected[1]);
			Kat256(m_message[2], m_expected[2]);
			Kat256(m_message[3], m_expected[3]);
			OnProgress(std::string("KeccakTest: Passed SHA3-256 bit digest vector tests.."));
			Kat512(m_message[0], m_expected[4]);
			Kat512(m_message[1], m_expected[5]);
			Kat512(m_message[2], m_expected[6]);
			Kat512(m_message[3], m_expected[7]);
			OnProgress(std::string("KeccakTest: Passed SHA3-512 bit digest vector tests.."));
			Kat1024(m_message[0], m_expected[8]);
			Kat1024(m_message[1], m_expected[9]);
			Kat1024(m_message[2], m_expected[10]);
			Kat1024(m_message[3], m_expected[11]);
			OnProgress(std::string("KeccakTest: Passed Keccak-1024 bit digest vector tests.."));

			Keccak256* dgt256s = new Keccak256(false);
			Stress(dgt256s);
			delete dgt256s;
			OnProgress(std::string("KeccakTest: Passed Keccak-256 sequential stress tests.."));

			Keccak512* dgt512s = new Keccak512(false);
			Stress(dgt512s);
			delete dgt512s;
			OnProgress(std::string("KeccakTest: Passed Keccak-512 sequential stress tests.."));

			Keccak1024* dgt1024s = new Keccak1024(false);
			Stress(dgt1024s);
			delete dgt1024s;
			OnProgress(std::string("KeccakTest: Passed Keccak-1024 sequential stress tests.."));

			if (detect.VirtualCores() >= 2)
			{
				Keccak256* dgt256p = new Keccak256(true);
				Stress(dgt256p);
				OnProgress(std::string("KeccakTest: Passed Keccak-256 parallel stress tests.."));

				Keccak512* dgt512p = new Keccak512(true);
				Stress(dgt512p);
				OnProgress(std::string("KeccakTest: Passed Keccak-512 parallel stress tests.."));

				Keccak1024* dgt1024p = new Keccak1024(true);
				Stress(dgt1024p);
				OnProgress(std::string("KeccakTest: Passed Keccak-1024 parallel stress tests.."));

				Parallel(dgt256p);
				delete dgt256p;
				OnProgress(std::string("KeccakTest: Passed Keccak-256 parallel tests.."));

				Parallel(dgt512p);
				delete dgt512p;
				OnProgress(std::string("KeccakTest: Passed Keccak-512 parallel tests.."));

				Parallel(dgt1024p);
				delete dgt1024p;
				OnProgress(std::string("KeccakTest: Passed Keccak-1024 parallel tests.."));
			}

			TreeParams();
			OnProgress(std::string("KeccakTest: Passed KeccakParams parameter serialization test.."));

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

	void KeccakTest::Exception()
	{
		// test params constructor Keccak256
		try
		{
			// invalid fan out -99
			KeccakParams params(32, 32, 99);
			Keccak256 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE1"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor Keccak512
		try
		{
			// invalid fan out -99
			KeccakParams params(64, 64, 99);
			Keccak512 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE2"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor Keccak1024
		try
		{
			// invalid fan out -99
			KeccakParams params(128, 128, 99);
			Keccak1024 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -KE3"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree Keccak256
		try
		{
			Keccak256 dgt;
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

		// test parallel max-degree Keccak512
		try
		{
			Keccak512 dgt;
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

		// test parallel max-degree Keccak1024
		try
		{
			Keccak1024 dgt;
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

	void KeccakTest::Kat256(std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> otp(32);
		Keccak256 dgt(false);

		dgt.Update(Message, 0, Message.size());
		dgt.Finalize(otp, 0);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat256"), dgt.Name(), std::string("Expected hash is not equal! -KK1"));
		}
	}

	void KeccakTest::Kat512(std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> otp(64);
		Keccak512 dgt(false);

		dgt.Update(Message, 0, Message.size());
		dgt.Finalize(otp, 0);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat512"), dgt.Name(), std::string("Expected hash is not equal! -KK2"));
		}
	}

	void KeccakTest::Kat1024(std::vector<byte> &Message, std::vector<byte> &Expected)
	{
		std::vector<byte> otp(128);
		Keccak1024 dgt(false);

		dgt.Update(Message, 0, Message.size());
		dgt.Finalize(otp, 0);

		if (otp != Expected)
		{
			throw TestException(std::string("Kat1024"), dgt.Name(), std::string("Expected hash is not equal! -KK3"));
		}
	}

	void KeccakTest::Parallel(IDigest* Digest)
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
				Digest->ParallelProfile().ParallelBlockSize() = PRLLEN;
			}
			catch (std::exception const&)
			{
				throw TestException(std::string("Parallel"), Digest->Name(), std::string("Parallel integrity test has failed! -BP1"));
			}
		}
	}

	void KeccakTest::PermutationR24()
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

	void KeccakTest::PermutationR48()
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

	void KeccakTest::Stress(IDigest* Digest)
	{
		const uint MINPRL = static_cast<uint>(Digest->ParallelProfile().ParallelMinimumSize());
		const uint MAXPRL = static_cast<uint>(Digest->ParallelProfile().ParallelBlockSize());

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

	void KeccakTest::TreeParams()
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

	void KeccakTest::Initialize()
	{
		/*lint -save -e417 */
		const std::vector<std::string> expected =
		{
			std::string("A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A"),
			std::string("3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532"),
			std::string("41C0DBA2A9D6240849100376A8235E2C82E1B9998A999E21DB32DD97496D3376"),
			std::string("79F38ADEC5C20307A98EF76E8324AFBFD46CFD81B22E3973C65FA1BD9DE31787"),
			std::string("A69F73CCA23A9AC5C8B567DC185A756E97C982164FE25859E0D1DCC1475C80A6"
				"15B2123AF1F5F94C11E3E9402C3AC558F500199D95B6D3E301758586281DCD26"),
			std::string("B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E"
				"10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0"),
			std::string("04A371E84ECFB5B8B77CB48610FCA8182DD457CE6F326A0FD3D7EC2F1E91636D"
				"EE691FBE0C985302BA1B0D8DC78C086346B533B49C030D99A27DAF1139D6E75E"),
			std::string("E76DFAD22084A8B1467FCF2FFA58361BEC7628EDF5F3FDC0E4805DC48CAEECA8"
				"1B7C13C30ADF52A3659584739A2DF46BE589C51CA1A4A8416DF6545A1CE8BA00"),
			std::string("8865E419509F0CFBB8366F0AE6742BCB2B519FB490E2D0B65E553BBFAF109631"
				"4F85EA9D571963ADF4FE178C62402AE4C19D890C58547A12A5EA54EE256B9295"
				"4F20257829A51A3F4AE039D699CA7DD280849DE3CD0EFDF53CC4306D22D98172"
				"BE81D5A2ED864AF9FE66962D25A992212D1841493D5B705DDD9A7015B1D7F77F"),
			std::string("FDF6E604576AC811ED4C56B622ED96DB05DB69009CBE6BC1F3FD6290E28DC45E"
				"618C5B121F21A104007763F42A845FE07717D5397C926E15C1358A0145BAE19A"
				"6A9C686095C6AEDDC82A694B822BD7196611F6FF47097D26FCCF6E6FC0A62F43"
				"3B61B879B1E455AECEF8CBF05877B064951DF191DF7C7F03B650A7BA97DC364C"),
			std::string("7A249A8B16A498972251B3E1505AE7643E11298D3906A9109D8B8879C9FB2780"
				"0A99E7D1E35DAEBA15EC8E5F197050EEE06A754DA93CA734756363DC7C71587C"
				"2532479B27AD5C98B943293397AB0D18AE2CEA7650E6F3F5768EAC6724943BBD"
				"118FF0D90F09C56391DAE15F3F09D0D42480EA9F55CD1E2A308CA915E9D1F7CA"),
			std::string("8AB191D915937401AD20EA293A5CC133D701E3D6839589BF817DE4974B2636AC"
				"9D9028BBE219B62F02CDB2862182CD252712C4886D7165F627E3D43487EDBBD5"
				"7ECE1F528B7BF214F0168BA89DDD91880A1EFEFF29AFB7EAFF3E62D5BCE43D24"
				"BA3A2659C2843D22D6A183C68E7432F28C34DC2597B958D80452B22F21AA9D40")
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

	void KeccakTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
