#include "Blake2Test.h"
#include "HexConverter.h"
#include "../CEX/Blake2.h"
#include "../CEX/Blake256.h"
#include "../CEX/Blake512.h"
#include "../CEX/CSP.h"
#include "../CEX/IntUtils.h"
#include "../CEX/MemUtils.h"
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
	using Utility::MemUtils;

#if defined(__AVX2__)
	using Numeric::UInt256;
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::UInt512;
	using Numeric::ULong512;
#endif

	using namespace TestFiles::Blake2Kat;

	const std::string Blake2Test::DESCRIPTION = "Blake Vector KATs; tests Blake2 256/512 digests.";
	const std::string Blake2Test::FAILURE = "FAILURE! ";
	const std::string Blake2Test::SUCCESS = "SUCCESS! All Blake tests have executed succesfully.";
	const std::string Blake2Test::DMK_INP = "in:	";
	const std::string Blake2Test::DMK_KEY = "key:	";
	const std::string Blake2Test::DMK_HSH = "hash:	";

	Blake2Test::Blake2Test()
		:
		m_expected(0),
		m_message(0),
		m_progressEvent()
	{
	}

	Blake2Test::~Blake2Test()
	{
	}

	const std::string Blake2Test::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &Blake2Test::Progress()
	{
		return m_progressEvent;
	}

	std::string Blake2Test::Run()
	{
		try
		{
			ComparePermutation256();
			OnProgress(std::string("Passed Blake2-256 permutation variants equivalence test.."));
			ComparePermutation512();
			OnProgress(std::string("Passed Blake2-512 permutation variants equivalence test.."));
			TreeParamsTest();
			OnProgress(std::string("Passed Blake2Params parameter serialization test.."));
			MacParamsTest();
			OnProgress(std::string("Passed SymmetricKey cloning test.."));
			Blake2STest();
			OnProgress(std::string("Passed Blake2-S 256 vector tests.."));
			Blake2SPTest();
			OnProgress(std::string("Passed Blake2-SP 256 vector tests.."));
			Blake2BTest();
			OnProgress(std::string("Passed Blake2-B 512 vector tests.."));
			Blake2BPTest();
			OnProgress(std::string("Passed Blake2-BP 512 vector tests.."));    

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

	void Blake2Test::Blake2BTest()
	{
		std::ifstream stream(BLAKE2BKAT);
		if (!stream)
		{
			throw TestException("Could not open file: " + BLAKE2BKAT);
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

					Key::Symmetric::SymmetricKey mkey(key);
					Blake512 blake2b(false);
					blake2b.Initialize(mkey);
					blake2b.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException("Blake2BTest: KAT test has failed!");
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2BPTest()
	{
		std::ifstream stream(BLAKE2BPKAT);
		if (!stream)
		{
			throw TestException("Could not open file: " + BLAKE2BPKAT);
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
					Key::Symmetric::SymmetricKey mkey(key);
					// hard code for test
					blake2bp.ParallelProfile().SetMaxDegree(4);
					blake2bp.Initialize(mkey);
					blake2bp.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException("Blake2BPTest: KAT test has failed!");
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2STest()
	{
		std::ifstream stream(BLAKE2SKAT);
		if (!stream)
		{
			throw TestException("Could not open file: " + BLAKE2SKAT);
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

					Key::Symmetric::SymmetricKey mkey(key);
					Blake256 blake2s(false);
					blake2s.Initialize(mkey);
					blake2s.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException("Blake2STest: KAT test has failed!");
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2SPTest()
	{
		std::ifstream stream(BLAKE2SPKAT);
		if (!stream)
		{
			throw TestException("Could not open file: " + BLAKE2SPKAT);
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

					Key::Symmetric::SymmetricKey mkey(key);
					Blake256 blake2sp(true);
					// hard code for test
					blake2sp.ParallelProfile().SetMaxDegree(8);
					blake2sp.Initialize(mkey);
					blake2sp.Compute(input, hash);

					if (hash != expect)
					{
						throw TestException("Blake2SPTest: KAT test has failed!");
					}
				}
			}
		}
		stream.close();
	}

	void Blake2Test::ComparePermutation256()
	{
		std::vector<byte> input(64, 128U);
		std::array<uint, 8> iv{ 0, 1, 2, 3, 4, 5, 6, 7 };
		std::array<uint, 8> state1;
		std::array<uint, 8> state2;
		std::array<uint, 8> state3;

		MemUtils::Clear(state1, 0, 8 * sizeof(uint));
		MemUtils::Clear(state2, 0, 8 * sizeof(uint));
		MemUtils::Clear(state3, 0, 8 * sizeof(uint));

		Blake2::PermuteR10P512C(input, 0, state1, iv);
		Blake2::PermuteR10P512U(input, 0, state2, iv);

#if defined(__AVX2__)

		Blake2::PermuteR10P512V(input, 0, state3, iv);

		if (state1 != state3)
		{
			throw TestException("Blake2 Permutation: Permutation output is not equal!");
		}

#endif

		if (state1 != state2)
		{
			throw TestException("Blake2 Permutation: Permutation output is not equal!");
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128UL);
		std::vector<UInt256> iv256{ UInt256(0), UInt256(1), UInt256(2), UInt256(3), UInt256(4), UInt256(5), UInt256(6), UInt256(7) };
		std::vector<UInt256> state256(8, UInt256(0));

		Blake2::PermuteR10P4096H(input256, 0, state256, iv256);

		std::vector<uint> state256ul(32);
		MemUtils::Copy(state256, 0, state256ul, 0, 32 * sizeof(uint));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ul[i] != state1[i / 8])
			{
				throw TestException("Blake2 Permutation: Permutation output is not equal!");
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<UInt512> iv512{ UInt512(0), UInt512(1), UInt512(2), UInt512(3), UInt512(4), UInt512(5), UInt512(6), UInt512(7) };
		std::vector<UInt512> state512(8, UInt512(0));

		Blake2::PermuteR10P8192H(input512, 0, state512, iv512);

		std::vector<uint> state512ul(64);
		MemUtils::Copy(state512, 0, state512ul, 0, 64 * sizeof(uint));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ul[i] != state1[i / 16])
			{
				throw TestException("Blake2 Permutation: Permutation output is not equal!");
			}
		}

#endif
	}

	void Blake2Test::ComparePermutation512()
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
			throw TestException("Blake2 Permutation: Permutation output is not equal!");
		}

#endif

		if (state1 != state2)
		{
			throw TestException("Blake2 Permutation: Permutation output is not equal!");
		}

#if defined(__AVX2__)

		std::vector<byte> input256(512, 128U);
		std::vector<ULong256> iv256{ ULong256(0), ULong256(1), ULong256(2), ULong256(3), ULong256(4), ULong256(5), ULong256(6), ULong256(7) };
		std::vector<ULong256> state256(8, ULong256(0));

		Blake2::PermuteR12P4096H(input256, 0, state256, iv256);

		std::vector<ulong> state256ull(32);
		MemUtils::Copy(state256, 0, state256ull, 0, 32 * sizeof(ulong));

		for (size_t i = 0; i < 32; ++i)
		{
			if (state256ull[i] != state1[i / 4])
			{
				throw TestException("Blake2 Permutation: Permutation output is not equal!");
			}
		}

#endif

#if defined(__AVX512__)

		std::vector<byte> input512(1024, 128U);
		std::vector<ULong512> iv512{ ULong512(0), ULong512(1), ULong512(2), ULong512(3), ULong512(4), ULong512(5), ULong512(6), ULong512(7) };
		std::vector<ULong512> state512(8, ULong512(0));

		Blake2::PermuteR12P8192H(input512, 0, state512, iv512);

		std::vector<ulong> state512ull(64);
		MemUtils::Copy(state512, 0, state512ull, 0, 64 * sizeof(ulong));

		for (size_t i = 0; i < 64; ++i)
		{
			if (state512ull[i] != state1[i / 8])
			{
				throw TestException("Blake2 Permutation: Permutation output is not equal!");
			}
		}

#endif
	}

	void Blake2Test::MacParamsTest()
	{
		std::vector<byte> key(64);
		for (byte i = 0; i < key.size(); ++i)
		{
			key[i] = i;
		}

		Key::Symmetric::SymmetricKey mkey(key, key, key);
		Key::Symmetric::ISymmetricKey* mkey2 = mkey.Clone();

		if (!mkey.Equals(*mkey2))
		{
			throw TestException("Blake2STest: Mac parameters test failed!");
		}
	}

	void Blake2Test::TreeParamsTest()
	{
		std::vector<byte> code1(40, 7);

		BlakeParams tree1(64, 64, 2, 1, 64000, 64, 1, 32, code1);
		std::vector<byte> tres = tree1.ToBytes();
		BlakeParams tree2(tres);

		if (!tree1.Equals(tree2))
		{
			throw std::string("Blake2STest: Tree parameters test failed!");
		}

		std::vector<byte> code2(12, 3);
		BlakeParams tree3(32, 32, 2, 1, 32000, 32, 1, 32, code1);
		tres = tree3.ToBytes();
		BlakeParams tree4(tres);

		if (!tree3.Equals(tree4))
		{
			throw std::string("Blake2STest: Tree parameters test failed!");
		}
	}

	void Blake2Test::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}
