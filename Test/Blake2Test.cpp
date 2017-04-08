#include "Blake2Test.h"
#include "HexConverter.h"
#include "../CEX/CSP.h"
#include "../CEX/Blake256.h"
#include "../CEX/Blake512.h"
#include "../CEX/SymmetricKey.h"
#include <fstream>
#include <string>

namespace Test
{
	using Digest::BlakeParams;
	using Digest::Blake256;
	using Digest::Blake512;
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

	std::string Blake2Test::Run()
	{
		try
		{
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
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Unknown Error"));
		}
	}

	void Blake2Test::Blake2BTest()
	{
		std::ifstream stream(BLAKE2BKAT);
		if (!stream)
			throw TestException("Could not open file: " + BLAKE2BKAT);

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<uint8_t> input(0);
					std::vector<uint8_t> expect(64);
					std::vector<uint8_t> key;
					std::vector<uint8_t> hash(64);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);

					Key::Symmetric::SymmetricKey mkey(key);
					Blake512 blake2b(false);
					blake2b.Initialize(mkey);
					blake2b.Compute(input, hash);

					if (hash != expect)
						throw TestException("Blake2BTest: KAT test has failed!");
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2BPTest()
	{
		std::ifstream stream(BLAKE2BPKAT);
		if (!stream)
			throw TestException("Could not open file: " + BLAKE2BPKAT);

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<uint8_t> input(0);
					std::vector<uint8_t> expect(64);
					std::vector<uint8_t> key;
					std::vector<uint8_t> hash(64);
					std::vector<uint8_t> hash2(64);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);

					// Note: the official default is 4 threads, my default on all digests is 8 threads
					BlakeParams params(64, 2, 4, 0, 64);
					Blake512 blake2bp(params);
					Key::Symmetric::SymmetricKey mkey(key);
					// hard code for test
					blake2bp.ParallelProfile().SetMaxDegree(4);
					blake2bp.Initialize(mkey);
					blake2bp.Compute(input, hash);

					if (hash != expect)
						throw TestException("Blake2BPTest: KAT test has failed!");
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2STest()
	{
		std::ifstream stream(BLAKE2SKAT);
		if (!stream)
			throw TestException("Could not open file: " + BLAKE2SKAT);

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<uint8_t> input(0);
					std::vector<uint8_t> expect(32);
					std::vector<uint8_t> key;
					std::vector<uint8_t> hash(32);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);

					Key::Symmetric::SymmetricKey mkey(key);
					Blake256 blake2s(false);
					blake2s.Initialize(mkey);
					blake2s.Compute(input, hash);

					if (hash != expect)
						throw TestException("Blake2STest: KAT test has failed!");
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2SPTest()
	{
		std::ifstream stream(BLAKE2SPKAT);
		if (!stream)
			throw TestException("Could not open file: " + BLAKE2SPKAT);

		std::string line;

		while (std::getline(stream, line))
		{
			if (line.size() != 0)
			{
				if (line.find(DMK_INP) != std::string::npos)
				{
					std::vector<uint8_t> input(0);
					std::vector<uint8_t> expect(32);
					std::vector<uint8_t> key;
					std::vector<uint8_t> hash(32);

					size_t sze = DMK_INP.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), input);

					std::getline(stream, line);
					sze = DMK_KEY.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), key);

					std::getline(stream, line);
					sze = DMK_HSH.length();
					if (line.length() - sze > 0)
						HexConverter::Decode(line.substr(sze, line.length() - sze), expect);

					Key::Symmetric::SymmetricKey mkey(key);
					Blake256 blake2sp(true);
					// hard code for test
					blake2sp.ParallelProfile().SetMaxDegree(8);
					blake2sp.Initialize(mkey);
					blake2sp.Compute(input, hash);

					if (hash != expect)
						throw TestException("Blake2SPTest: KAT test has failed!");
				}
			}
		}
		stream.close();
	}

	void Blake2Test::MacParamsTest()
	{
		std::vector<uint8_t> key(64);
		for (uint8_t i = 0; i < key.size(); ++i)
			key[i] = i;

		Key::Symmetric::SymmetricKey mkey(key, key, key);
		Key::Symmetric::ISymmetricKey* mkey2 = mkey.Clone();

		if (!mkey.Equals(*mkey2))
			throw TestException("Blake2STest: Mac parameters test failed!");
	}

	void Blake2Test::TreeParamsTest()
	{
		std::vector<byte> code1(40, 7);

		BlakeParams tree1(64, 64, 2, 1, 64000, 64, 1, 32, code1);
		std::vector<uint8_t> tres = tree1.ToBytes();
		BlakeParams tree2(tres);

		if (!tree1.Equals(tree2))
			throw std::string("Blake2STest: Tree parameters test failed!");

		std::vector<byte> code2(12, 3);
		BlakeParams tree3(32, 32, 2, 1, 32000, 32, 1, 32, code1);
		tres = tree3.ToBytes();
		BlakeParams tree4(tres);

		if (!tree3.Equals(tree4))
			throw std::string("Blake2STest: Tree parameters test failed!");
	}

	void Blake2Test::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}