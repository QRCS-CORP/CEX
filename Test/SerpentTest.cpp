#include "SerpentTest.h"
#include "SHX.h"
#include "IntUtils.h"

namespace Test
{
	std::string SerpentTest::Run()
	{
		try
		{
			using namespace TestFiles::Nessie;

			std::vector<byte> cip(16, 0);
			std::vector<byte> key(16, 0);
			std::vector<byte> pln(16, 0);
			std::vector<byte> mnt(16, 0);
			int rcount = 0;

			// 128 bit keys
			std::string cipStr;
			std::string keyStr;
			std::string plnStr;
			std::string mntStr;
			std::string mnt1kStr;

			TestUtils::Read(serpentcipher128, cipStr);
			TestUtils::Read(serpentkey128, keyStr);
			TestUtils::Read(serpentplain128, plnStr);
			TestUtils::Read(serpentmonte100_128, mntStr);
			TestUtils::Read(serpentmonte1000_128, mnt1kStr);

			for (unsigned int i = 0; i < keyStr.size(); i += 32)
			{
				// less monte carlo tests than vector
				bool doMonte = i * 32 < mntStr.size();

				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(i, 32), key);
				HexConverter::Decode(plnStr.substr(i, 32), pln);

				// reversed endian order in Nessie test vectors
				TestUtils::Reverse(key);
				TestUtils::Reverse(cip);
				TestUtils::Reverse(pln);

				if (doMonte)
				{
					HexConverter::Decode(mntStr.substr(i, 32), mnt);
					TestUtils::Reverse(mnt);
					// monte carlo 100 rounds
					CompareMonteCarlo(key, pln, mnt);
					rcount += 100;
					// 1000 rounds
					HexConverter::Decode(mnt1kStr.substr(i, 32), mnt);
					TestUtils::Reverse(mnt);
					CompareMonteCarlo(key, pln, mnt, 1000);
					rcount += 1000;
				}

				// vector comparison
				CompareVector(key, pln, cip);
			}

			std::string rcnt = CEX::Utility::IntUtils::ToString(rcount);
			std::string klen = CEX::Utility::IntUtils::ToString((int)(keyStr.size() / 32));
			std::string resp = "Serpent128: Passed Monte Carlo " + rcnt + (std::string)" rounds and " + klen + (std::string)" vectors..";
			OnProgress(const_cast<char*>(resp.c_str()));
			rcount = 0;

			// 192 bit keys
			TestUtils::Read(serpentcipher192, cipStr);
			TestUtils::Read(serpentkey192, keyStr);
			TestUtils::Read(serpentplain192, plnStr);
			TestUtils::Read(serpentmonte100_192, mntStr);
			TestUtils::Read(serpentmonte1000_192, mnt1kStr);

			for (unsigned int i = 0, j = 0; j < keyStr.size(); i += 32, j += 48)
			{
				bool doMonte = i * 32 < mntStr.size();

				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(j, 48), key);
				HexConverter::Decode(plnStr.substr(i, 32), pln);

				TestUtils::Reverse(key);
				TestUtils::Reverse(cip);
				TestUtils::Reverse(pln);

				if (doMonte)
				{
					HexConverter::Decode(mntStr.substr(i, 32), mnt);
					TestUtils::Reverse(mnt);
					// monte carlo 100 rounds
					CompareMonteCarlo(key, pln, mnt);
					rcount += 100;
					// 1000 rounds
					HexConverter::Decode(mnt1kStr.substr(i, 32), mnt);
					TestUtils::Reverse(mnt);
					CompareMonteCarlo(key, pln, mnt, 1000);
					rcount += 1000;
				}

				// vector comparison
				CompareVector(key, pln, cip);
			}

			rcnt = CEX::Utility::IntUtils::ToString(rcount);
			klen = CEX::Utility::IntUtils::ToString((int)(keyStr.size() / 32));
			resp = "Serpent192: Passed Monte Carlo " + rcnt + (std::string)" rounds and " + klen + (std::string)" vectors..";
			OnProgress(const_cast<char*>(resp.c_str()));

			rcount = 0;

			// 256 bit keys
			TestUtils::Read(serpentcipher256, cipStr);
			TestUtils::Read(serpentkey256, keyStr);
			TestUtils::Read(serpentplain256, plnStr);
			TestUtils::Read(serpentmonte100_256, mntStr);
			TestUtils::Read(serpentmonte1000_256, mnt1kStr);

			for (unsigned int i = 0, j = 0; j < keyStr.size(); i += 32, j += 64)
			{
				bool doMonte = i * 32 < mntStr.size();

				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(j, 64), key);
				HexConverter::Decode(plnStr.substr(i, 32), pln);

				TestUtils::Reverse(key);
				TestUtils::Reverse(cip);
				TestUtils::Reverse(pln);

				if (doMonte)
				{
					HexConverter::Decode(mntStr.substr(i, 32), mnt);
					TestUtils::Reverse(mnt);
					// monte carlo 100 rounds
					CompareMonteCarlo(key, pln, mnt);
					rcount += 100;
					// 1000 rounds
					HexConverter::Decode(mnt1kStr.substr(i, 32), mnt);
					TestUtils::Reverse(mnt);
					CompareMonteCarlo(key, pln, mnt, 1000);
					rcount += 1000;
				}

				// vector comparison
				CompareVector(key, pln, cip);
			}

			rcnt = CEX::Utility::IntUtils::ToString(rcount);
			klen = CEX::Utility::IntUtils::ToString((int)(keyStr.size() / 32));
			resp = "Serpent256: Passed Monte Carlo " + rcnt + (std::string)" rounds and " + klen + (std::string)" vectors..";
			OnProgress(const_cast<char*>(resp.c_str()));
			rcount = 0;

			// 512 bit key encrypt/decrypt self-test
			CompareOutput();
			OnProgress("SerpentTest: Passed 512 bit key self test..");

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

	void SerpentTest::CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, unsigned int Count)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		memcpy(&outBytes[0], &Input[0], outBytes.size());
		CEX::Cipher::Symmetric::Block::SHX eng;
		CEX::Common::KeyParams k(Key);

		eng.Initialize(true, k);

		for (unsigned int i = 0; i != Count; i++)
			eng.Transform(outBytes, outBytes);

		if (outBytes != Output)
			throw std::string("Serpent MonteCarlo: Arrays are not equal!");
	}

	void SerpentTest::CompareOutput()
	{
		std::vector<byte> inBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> decBytes(16, 0);
		std::vector<byte> key(64, 0);

		for (unsigned int i = 0; i < 16; i++)
			inBytes[i] = (byte)i;
		for (unsigned int i = 0; i < 64; i++)
			key[i] = (byte)i;

		CEX::Cipher::Symmetric::Block::SHX eng;
		CEX::Common::KeyParams k(key);

		eng.Initialize(true, k);
		eng.EncryptBlock(inBytes, outBytes);

		eng.Initialize(false, k);
		eng.DecryptBlock(outBytes, decBytes);

		if (inBytes != decBytes)
			throw std::string("Serpent: Decrypted arrays are not equal!");
	}

	void SerpentTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> outBytes(Output.size(), 0);
		CEX::Cipher::Symmetric::Block::SHX enc;
		CEX::Common::KeyParams k(Key);
		enc.Initialize(true, k);
		enc.EncryptBlock(Input, outBytes);

		if (Output != outBytes)
			throw std::string("Serpent Vector: Arrays are not equal!");

		CEX::Cipher::Symmetric::Block::SHX dec;
		//CEX::Common::KeyParams k2(Key);
		dec.Initialize(false, k);
		dec.DecryptBlock(Output, outBytes);

		if (Input != outBytes)
			throw std::string("Serpent Vector: Arrays are not equal!");
	}

	void SerpentTest::OnProgress(char* Data)
	{
		m_progressEvent(Data);
	}
}