#include "Blake2Test.h"
#include "HexConverter.h"
#include "../CEX/Blake2.h"
#include "../CEX/Blake256.h"
#include "../CEX/Blake512.h"
#include "../CEX/CpuDetect.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"
#include <fstream>
#include <string>

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
	using Digest::Blake2;
	using Digest::Blake256;
	using Digest::Blake512;
	using Digest::BlakeParams;
	using Exception::CryptoDigestException;
	using Utility::IntegerTools;
	using Utility::MemoryTools;
	using Prng::SecureRandom;
#if defined(__AVX2__)
	using Numeric::UInt256;
	using Numeric::ULong256;
#endif
#if defined(__AVX512__)
	using Numeric::UInt512;
	using Numeric::ULong512;
#endif

	using namespace TestFiles::Blake2Kat;

	const std::string Blake2Test::CLASSNAME = "Blake2Test";
	const std::string Blake2Test::DESCRIPTION = "Blake Vector KATs; tests Blake2 256/512 digests."; // TODO: update all of these, headers too
	const std::string Blake2Test::SUCCESS = "SUCCESS! All Blake tests have executed succesfully.";
	const std::string Blake2Test::DMK_INP = "in:	";
	const std::string Blake2Test::DMK_KEY = "key:	";
	const std::string Blake2Test::DMK_HSH = "hash:	";

	//~~~Constructor~~~//

	Blake2Test::Blake2Test()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
	}

	Blake2Test::~Blake2Test()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_message);
	}

	//~~~Accessors~~~//

	const std::string Blake2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &Blake2Test::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string Blake2Test::Run()
	{
		try
		{
			CpuDetect detect;

			Exception();
			OnProgress(std::string("Blake2Test: Passed Blake2-256/512 exception handling tests.."));
			KatBlake2S();
			OnProgress(std::string("Blake2Test: Passed Blake2-S 256 vector tests.."));
			KatBlake2SP();
			OnProgress(std::string("Blake2Test: Passed Blake2-SP 256 vector tests.."));
			KatBlake2B();
			OnProgress(std::string("Blake2Test: Passed Blake2-B 512 vector tests.."));
			KatBlake2BP();
			OnProgress(std::string("Blake2Test: Passed Blake2-BP 512 vector tests.."));
			PermutationR10P512();
			OnProgress(std::string("Blake2Test: Passed Blake2-256 permutation variants equivalence test.."));
			PermutationR12P1024();
			OnProgress(std::string("Blake2Test: Passed Blake2-512 permutation variants equivalence test.."));

			Blake256* dgt256s = new Blake256(false);
			Stress(dgt256s);
			delete dgt256s;
			OnProgress(std::string("Blake2Test: Passed Passed Blake2-S sequential stress tests.."));

			Blake512* dgt512s = new Blake512(false);
			Stress(dgt512s);
			delete dgt512s;
			OnProgress(std::string("Blake2Test: Passed Passed Blake2-B sequential stress tests.."));

			if (detect.VirtualCores() >= 2)
			{
				Blake256* dgt256p = new Blake256(true);
				Stress(dgt256p);
				OnProgress(std::string("Blake2Test: Passed Passed Blake2-SP parallel stress tests.."));

				Blake512* dgt512p = new Blake512(true);
				Stress(dgt512p);
				OnProgress(std::string("Blake2Test: Passed Passed Blake2-BP parallel stress tests.."));

				Parallel(dgt256p);
				delete dgt256p;
				OnProgress(std::string("Blake2Test: Passed Blake2-SP 256 parallel tests.."));

				Parallel(dgt512p);
				delete dgt512p;
				OnProgress(std::string("Blake2Test: Passed Blake2-BP 512 parallel tests.."));
			}

			TreeParams();
			OnProgress(std::string("Blake2Test: Passed Blake2Params parameter serialization test.."));

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

	void Blake2Test::Exception()
	{
		// test params constructor Blake256
		try
		{
			// invalid leaf length -99
			BlakeParams params(64, 2, 99, 0, 64);
			Blake256 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -BE1"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test params constructor Blake512
		try
		{
			// invalid leaf length -99
			BlakeParams params(128, 2, 99, 0, 128);
			Blake512 dgt(params);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -BE2"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree Blake256
		try
		{
			Blake256 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -BE3"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test parallel max-degree Blake512
		try
		{
			Blake512 dgt;
			// set max degree to invalid -99
			dgt.ParallelMaxDegree(99);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -BE4"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test mac key size Blake256
		try
		{
			Blake256 dgt;
			// set mac key to an invalid size -99
			std::vector<byte> k(99);
			Cipher::SymmetricKey kp(k);
			dgt.Initialize(kp);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -BE5"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test mac key size Blake512
		try
		{
			Blake512 dgt;
			// set mac key to an invalid size -99
			std::vector<byte> k(99);
			Cipher::SymmetricKey kp(k);
			dgt.Initialize(kp);

			throw TestException(std::string("Exception"), dgt.Name(), std::string("Exception handling failure! -BE6"));
		}
		catch (CryptoDigestException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void Blake2Test::PermutationR10P512()
	{
		std::vector<byte> input(64, 128U);
		std::array<uint, 8> iv{ 0, 1, 2, 3, 4, 5, 6, 7 };
		std::array<uint, 8> state1;
		std::array<uint, 8> state2;
		std::array<uint, 8> state3;

		MemoryTools::Clear(state1, 0, 8 * sizeof(uint));
		MemoryTools::Clear(state2, 0, 8 * sizeof(uint));
		MemoryTools::Clear(state3, 0, 8 * sizeof(uint));

		Blake2::PermuteR10P512C(input, 0, state1, iv);
		Blake2::PermuteR10P512U(input, 0, state2, iv);

#if defined(__AVX2__)

		Blake2::PermuteR10P512V(input, 0, state3, iv);

		if (state1 != state3)
		{
			throw TestException(std::string("PermutationR10P512"), std::string("PermuteR10P512"), std::string("Permutation output is not equal! -BCS1"));
		}

#endif

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR10P512"), std::string("PermuteR10P512"), std::string("Permutation output is not equal! -BCS2"));
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128UL);
		std::vector<UInt256> iv256{ UInt256(0), UInt256(1), UInt256(2), UInt256(3), UInt256(4), UInt256(5), UInt256(6), UInt256(7) };
		std::vector<UInt256> state256(8, UInt256(0));

		Blake2::PermuteR10P8x512H(input256, 0, state256, iv256);

		std::vector<uint> state256ul(32);
		std::memcpy(state256ul.data(), state256.data(), 32 * sizeof(uint));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ul[i] != state1[i / 8])
			{
				throw TestException(std::string("PermutationR10P512"), std::string("PermuteR10P8x512H"), std::string("Permutation output is not equal! -BCS3"));
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<UInt512> iv512{ UInt512(0), UInt512(1), UInt512(2), UInt512(3), UInt512(4), UInt512(5), UInt512(6), UInt512(7) };
		std::vector<UInt512> state512(8, UInt512(0));

		Blake2::PermuteR10P16x512H(input512, 0, state512, iv512);

		std::vector<uint> state512ul(64);
		std::memcpy(state512ul.data(), state512.data(), 64 * sizeof(uint));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ul[i] != state1[i / 16])
			{
				throw TestException(std::string("PermutationR10P512"), std::string("PermuteR10P16x512H"), std::string("Permutation output is not equal! -BCS4"));
			}
		}

#endif
	}

	void Blake2Test::PermutationR12P1024()
	{
		std::vector<byte> input(128, 128U);
		std::array<ulong, 8> iv{ 0, 1, 2, 3, 4, 5, 6, 7 };
		std::array<ulong, 8> state1;
		std::array<ulong, 8> state2;
		std::array<ulong, 8> state3;

		std::memset(state1.data(), 0, 8 * sizeof(ulong));
		std::memset(state2.data(), 0, 8 * sizeof(ulong));
		std::memset(state3.data(), 0, 8 * sizeof(ulong));

		Blake2::PermuteR12P1024C(input, 0, state1, iv);
		Blake2::PermuteR12P1024U(input, 0, state2, iv);

#if defined(__AVX2__)

		Blake2::PermuteR12P1024V(input, 0, state3, iv);

		if (state1 != state3)
		{
			throw TestException(std::string("PermutationR12P1024"), std::string("PermuteR12P1024"), std::string("Permutation output is not equal! -BCL1"));
		}

#endif

		if (state1 != state2)
		{
			throw TestException(std::string("PermutationR12P1024"), std::string("PermuteR12P1024"), std::string("Permutation output is not equal! -BCL2"));
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128U);
		std::vector<ULong256> iv256{ ULong256(0), ULong256(1), ULong256(2), ULong256(3), ULong256(4), ULong256(5), ULong256(6), ULong256(7) };
		std::vector<ULong256> state256(8, ULong256(0));

		Blake2::PermuteR12P4x1024H(input256, 0, state256, iv256);

		std::vector<ulong> state256ull(32);
		MemoryTools::Copy(state256, 0, state256ull, 0, 32 * sizeof(ulong));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ull[i] != state1[i / 4])
			{
				throw TestException(std::string("PermutationR12P1024"), std::string("PermuteR12P4x1024H"), std::string("Permutation output is not equal! -BCL3"));
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<ULong512> iv512{ ULong512(0), ULong512(1), ULong512(2), ULong512(3), ULong512(4), ULong512(5), ULong512(6), ULong512(7) };
		std::vector<ULong512> state512(8, ULong512(0));

		Blake2::PermuteR12P8x1024H(input512, 0, state512, iv512);

		std::vector<ulong> state512ull(64);
		MemoryTools::Copy(state512, 0, state512ull, 0, 64 * sizeof(ulong));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ull[i] != state1[i / 8])
			{
				throw TestException(std::string("PermutationR12P1024"), std::string("PermuteR12P8x1024H"), std::string("Permutation output is not equal! -BCL4"));
			}
		}

#endif
	}

	void Blake2Test::KatBlake2B()
	{
		std::ifstream stream(BLAKE2BKAT);
		if (!stream)
		{
			throw TestException(std::string("KatBlake2B"), std::string("BLAKE2BKAT"), std::string("Could not open file: ") + BLAKE2BKAT + std::string(" -BKB1"));
		}

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<byte> input(0);
					std::vector<byte> expect(64);
					std::vector<byte> key;
					std::vector<byte> hash(64);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);
					}

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);
					}

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);
					}

					Cipher::SymmetricKey mkey(key);
					Blake512 blake2b(false);
					blake2b.Initialize(mkey);
					blake2b.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException(std::string("KatBlake2B"), blake2b.Name(), std::string("KAT test has failed! -BKB2"));
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::KatBlake2BP()
	{
		std::ifstream stream(BLAKE2BPKAT);
		if (!stream)
		{
			throw TestException(std::string("KatBlake2BP"), std::string("BLAKE2BPKAT"), std::string("Could not open file: ") + BLAKE2BPKAT + std::string(" -BKBP1"));
		}

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<byte> input(0);
					std::vector<byte> expect(64);
					std::vector<byte> key;
					std::vector<byte> hash(64);
					std::vector<byte> hash2(64);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);
					}

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);
					}

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);
					}

					// Note: the official default is 4 threads, my default on all digests is 8 threads
					BlakeParams params(64, 2, 4, 0, 64);
					Blake512 blake2bp(params);
					Cipher::SymmetricKey mkey(key);
					// hard code for test
					blake2bp.ParallelProfile().SetMaxDegree(4);
					blake2bp.Initialize(mkey);
					blake2bp.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException(std::string("KatBlake2BP"), blake2bp.Name(), std::string("KAT test has failed! -BKBP2"));
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::KatBlake2S()
	{
		std::ifstream stream(BLAKE2SKAT);
		if (!stream)
		{
			throw TestException(std::string("KatBlake2S"), std::string("BLAKE2SKAT"), std::string("Could not open file: ") + BLAKE2SKAT + std::string(" -BKS1"));
		}

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<byte> input(0);
					std::vector<byte> expect(32);
					std::vector<byte> key;
					std::vector<byte> hash(32);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);
					}

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);
					}

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);
					}

					Cipher::SymmetricKey mkey(key);
					Blake256 blake2s(false);
					blake2s.Initialize(mkey);
					blake2s.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException(std::string("KatBlake2S"), blake2s.Name(), std::string("KAT test has failed! -BKS2"));
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::KatBlake2SP()
	{
		std::ifstream stream(BLAKE2SPKAT);
		if (!stream)
		{
			throw TestException(std::string("KatBlake2SP"), std::string("BLAKE2SPKAT"), std::string("Could not open file: ") + BLAKE2SPKAT + std::string(" -BKSP1"));
		}

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<byte> input(0);
					std::vector<byte> expect(32);
					std::vector<byte> key;
					std::vector<byte> hash(32);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);
					}

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);
					}

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
					{
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);
					}

					Cipher::SymmetricKey mkey(key);
					Blake256 blake2sp(true);
					// hard code for test
					blake2sp.ParallelProfile().SetMaxDegree(8);
					blake2sp.Initialize(mkey);
					blake2sp.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException(std::string("KatBlake2SP"), blake2sp.Name(), std::string("KAT test has failed! -BKSP2"));
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Parallel(IDigest* Digest)
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

	void Blake2Test::Stress(IDigest* Digest)
	{
		const uint MINPRL = static_cast<uint>(Digest->ParallelProfile().ParallelMinimumSize());
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
				throw TestException(std::string("Stress"), Digest->Name(), std::string("Stress: The digest has thrown an exception! -BS1"));
			}

			if (code1 != code2)
			{
				throw TestException(std::string("Stress"), Digest->Name(), std::string("Stress: Hash output is not equal! -BS2"));
			}
		}
	}

	void Blake2Test::TreeParams()
	{
		std::vector<byte> code1(40, 7);

		BlakeParams tree1(64, 64, 2, 1, 64000, 64, 1, 32, code1);
		std::vector<byte> tres = tree1.ToBytes();
		BlakeParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw TestException(std::string("TreeParams"), std::string("BlakeParams"), std::string("TreeParams: Tree parameters test failed! -BT1"));
		}

		std::vector<byte> code2(12, 3);
		BlakeParams tree3(32, 32, 2, 1, 32000, 32, 1, 32, code1);
		tres = tree3.ToBytes();
		BlakeParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw TestException(std::string("TreeParams"), std::string("BlakeParams"), std::string("TreeParams: Tree parameters test failed! -BT2"));
		}
	}

	//~~~Private Functions~~~//

	void Blake2Test::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
