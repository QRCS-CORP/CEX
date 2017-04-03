#include "Blake2Test.h"
#include <fstream>
#include <string>
#include "HexConverter.h"
#include "../CEX/CSP.h"
#include "../CEX/Blake256.h"
#include "../CEX/Blake512.h"
#include "../CEX/SymmetricKey.h"

namespace Test
{
	using Digest::BlakeParams;
	using Digest::Blake256;
	using Digest::Blake512;

	std::string Blake2Test::Run()
	{
		try
		{
			TreeParamsTest();
			OnProgress("Passed Blake2Params parameter serialization test..");
			MacParamsTest();
			OnProgress("Passed SymmetricKey cloning test..");
			Blake2STest();
			OnProgress("Passed Blake2-S 256 vector tests..");
			Blake2SPTest();
			OnProgress("Passed Blake2-SP 256 vector tests..");
			Blake2BTest();
			OnProgress("Passed Blake2-B 512 vector tests..");
			Blake2BPTest();
			OnProgress("Passed Blake2-BP 512 vector tests..");    

			return SUCCESS;
		}
		catch (std::exception const &ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex.what()));
		}
		catch (...)
		{
			throw TestException(std::string(FAILURE + " : Internal Error"));
		}
	}

	void Blake2Test::Blake2BTest()
	{
		std::ifstream stream("Vectors/Blake2/blake2b-kat.txt");
		if (!stream)
			std::cerr << "Could not open file" << std::endl;

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
		std::ifstream stream("Vectors/Blake2/blake2bp-kat.txt");
		if (!stream)
			std::cerr << "Could not open file" << std::endl;

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
					Blake512 blake2(params);
					Key::Symmetric::SymmetricKey mkey(key);
					blake2.Initialize(mkey);
					blake2.Compute(input, hash);

					if (hash != expect)
						throw TestException("Blake2BPTest: KAT test has failed!");
				}
			}
		}
		stream.close();
	}

	void Blake2Test::Blake2STest()
	{
		std::ifstream stream("Vectors/Blake2/blake2s-kat.txt");
		if (!stream)
			std::cerr << "Could not open file" << std::endl;

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
		std::ifstream stream("Vectors/Blake2/blake2sp-kat.txt");
		if (!stream)
			std::cerr << "Could not open file" << std::endl;

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

	void Blake2Test::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}