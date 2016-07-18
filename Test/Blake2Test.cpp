#include "Blake2Test.h"
#include <fstream>
#include <string.h>
#include "HexConverter.h"
#include "../CEX/CSPRsg.h"
#include "../CEX/Blake2Sp256.h"
#include "../CEX/Blake2Bp512.h"
#include "../CEX/MacParams.h"

namespace Test
{
	std::string Blake2Test::Run()
	{
		try
		{
			TreeParamsTest();
			OnProgress("Passed Blake2Params parameter serialization test..");
			MacParamsTest();
			OnProgress("Passed MacParams cloning test..");
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
		catch (std::string const& ex)
		{
			throw TestException(std::string(FAILURE + " : " + ex));
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

					CEX::Common::MacParams mkey(key);
					CEX::Digest::Blake2Bp512 blake2b(false);
					blake2b.LoadMacKey(mkey);
					blake2b.ComputeHash(input, hash);

					if (hash != expect)
						throw std::string("Blake2BTest: KAT test has failed!");
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

					CEX::Digest::Blake2Bp512 blake2(true);
					CEX::Common::MacParams mkey(key);
					blake2.LoadMacKey(mkey);
					blake2.ComputeHash(input, hash);

					if (hash != expect)
						throw std::string("Blake2BPTest: KAT test has failed!");
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

					CEX::Common::MacParams mkey(key);
					CEX::Digest::Blake2Sp256 blake2s(false);
					blake2s.LoadMacKey(mkey);
					blake2s.ComputeHash(input, hash);

					if (hash != expect)
						throw std::string("Blake2STest: KAT test has failed!");
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

					CEX::Common::MacParams mkey(key);
					CEX::Digest::Blake2Sp256 blake2sp(true);
					blake2sp.LoadMacKey(mkey);
					blake2sp.ComputeHash(input, hash);

					if (hash != expect)
						throw std::string("Blake2SPTest: KAT test has failed!");
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

		CEX::Common::MacParams mkey(key, key, key);
		CEX::Common::MacParams* mkey2 = mkey.DeepCopy();
		CEX::Common::MacParams mkey3 = mkey.Clone();

		if (!mkey.Equals(*mkey2) || !mkey.Equals(mkey3))
			throw std::string("Blake2STest: Mac parameters test failed!");
	}

	void Blake2Test::TreeParamsTest()
	{
		CEX::Digest::Blake2Params tree1(64, 64, 2, 1, 64000, 64, 1, 32, 0);
		std::vector<uint8_t> tres = tree1.ToBytes();
		CEX::Digest::Blake2Params tree2(tres);

		if (!tree1.Equals(tree2))
			throw std::string("Blake2STest: Tree parameters test failed!");
	}

	void Blake2Test::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}