#include "SerpentTest.h"
#include "../CEX/CTR.h"
#include "../CEX/SHX.h"
#include "../CEX/IntUtils.h"

namespace Test
{
	using namespace Cipher::Symmetric::Block;

	const std::string SerpentTest::DESCRIPTION = "Serpent Nessie tests, with 100 and 1000 round Monte Carlo runs.";
	const std::string SerpentTest::FAILURE = "FAILURE! ";
	const std::string SerpentTest::SUCCESS = "SUCCESS! All Serpent tests have executed succesfully.";

	SerpentTest::SerpentTest()
		:
		m_progressEvent()
	{
	}

	SerpentTest::~SerpentTest()
	{
	}

	std::string SerpentTest::Run()
	{
		try
		{
			using namespace TestFiles::Nessie;

			CompareOutput();

			std::vector<byte> cip(16, 0);
			std::vector<byte> key(16, 0);
			std::vector<byte> pln(16, 0);
			std::vector<byte> mnt(16, 0);
			int rcount = 0;

			// 128 bit keys
			std::string cipStr = "";
			std::string keyStr = "";
			std::string plnStr = "";
			std::string mntStr = "";
			std::string mnt1kStr = "";

			std::string rcnt; 
			std::string klen; 
			std::string resp;

			TestUtils::Read(SERPENTCTEXT128, cipStr);
			if (cipStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTKEY128, keyStr);
			if (keyStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTPTEXT128, plnStr);
			if (plnStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTM100X128, mntStr);
			if (mntStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTM1000X128, mnt1kStr);
			if (mnt1kStr.size() == 0)
				throw TestException("Could not find the test file!");


			for (unsigned int i = 0; i < keyStr.size(); i += 32)
			{
				// less monte carlo tests than vector
				bool doMonte = i * 32 < mntStr.size();

				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(i, 32), key);
				HexConverter::Decode(plnStr.substr(i, 32), pln);

				// *note* reversed endian ordered keys in Nessie test vectors
				TestUtils::Reverse(key);

				if (doMonte)
				{
					HexConverter::Decode(mntStr.substr(i, 32), mnt);
					// monte carlo 100 rounds
					CompareMonteCarlo(key, pln, mnt);
					rcount += 100;
					// 1000 rounds
					HexConverter::Decode(mnt1kStr.substr(i, 32), mnt);
					CompareMonteCarlo(key, pln, mnt, 1000);
					rcount += 1000;
				}

				// vector comparison
				CompareVector(key, pln, cip);
			}
			//
			rcnt = TestUtils::ToString(rcount);
			klen = TestUtils::ToString((int)(keyStr.size() / 32));
			resp = "Serpent128: Passed Monte Carlo " + rcnt + std::string(" rounds and " + klen + std::string(" vectors.."));
			OnProgress(resp);
			rcount = 0;

			cipStr = "";
			keyStr = "";
			plnStr = "";
			mntStr = "";
			mnt1kStr = "";

			// 192 bit keys
			TestUtils::Read(SERPENTCTEXT192, cipStr);
			if (cipStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTKEY192, keyStr);
			if (keyStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTPTEXT192, plnStr);
			if (plnStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTM100X192, mntStr);
			if (mntStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTM1000X192, mnt1kStr);
			if (mnt1kStr.size() == 0)
				throw TestException("Could not find the test file!");

			for (unsigned int i = 0, j = 0; j < keyStr.size(); i += 32, j += 48)
			{
				bool doMonte = i * 32 < mntStr.size();

				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(j, 48), key);
				HexConverter::Decode(plnStr.substr(i, 32), pln);
				TestUtils::Reverse(key);

				if (doMonte)
				{
					HexConverter::Decode(mntStr.substr(i, 32), mnt);
					// monte carlo 100 rounds
					CompareMonteCarlo(key, pln, mnt);
					rcount += 100;
					// 1000 rounds
					HexConverter::Decode(mnt1kStr.substr(i, 32), mnt);
					CompareMonteCarlo(key, pln, mnt, 1000);
					rcount += 1000;
				}

				// vector comparison
				CompareVector(key, pln, cip);
			}

			rcnt = TestUtils::ToString(rcount);
			klen = TestUtils::ToString((int)(keyStr.size() / 32));
			resp = "Serpent192: Passed Monte Carlo " + rcnt + std::string(" rounds and " + klen + std::string(" vectors.."));
			OnProgress(resp);
			rcount = 0;

			cipStr = "";
			keyStr = "";
			plnStr = "";
			mntStr = "";
			mnt1kStr = "";

			// 256 bit keys
			TestUtils::Read(SERPENTCTEXT256, cipStr);
			if (cipStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTKEY256, keyStr);
			if (keyStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTPTEXT256, plnStr);
			if (plnStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTM100X256, mntStr);
			if (mntStr.size() == 0)
				throw TestException("Could not find the test file!");
			TestUtils::Read(SERPENTM1000X256, mnt1kStr);
			if (mnt1kStr.size() == 0)
				throw TestException("Could not find the test file!");

			for (unsigned int i = 0, j = 0; j < keyStr.size(); i += 32, j += 64)
			{
				bool doMonte = i * 32 < mntStr.size();

				HexConverter::Decode(cipStr.substr(i, 32), cip);
				HexConverter::Decode(keyStr.substr(j, 64), key);
				HexConverter::Decode(plnStr.substr(i, 32), pln);
				TestUtils::Reverse(key);

				if (doMonte)
				{
					HexConverter::Decode(mntStr.substr(i, 32), mnt);
					// monte carlo 100 rounds
					CompareMonteCarlo(key, pln, mnt);
					rcount += 100;
					// 1000 rounds
					HexConverter::Decode(mnt1kStr.substr(i, 32), mnt);
					CompareMonteCarlo(key, pln, mnt, 1000);
					rcount += 1000;
				}

				// vector comparison
				CompareVector(key, pln, cip);
			}

			rcnt = TestUtils::ToString(rcount);
			klen = TestUtils::ToString((int)(keyStr.size() / 32));
			resp = "Serpent256: Passed Monte Carlo " + rcnt + std::string(" rounds and " + klen + std::string(" vectors.."));
			OnProgress(resp);
			rcount = 0;

			// 512 bit key encrypt/decrypt self-test
			CompareOutput();
			OnProgress(std::string("SerpentTest: Passed 512 bit key self test.."));

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

	void SerpentTest::CompareMonteCarlo(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output, unsigned int Count)
	{
		std::vector<byte> outBytes(Input.size(), 0);
		memcpy(&outBytes[0], &Input[0], outBytes.size());
		SHX eng;
		Key::Symmetric::SymmetricKey k(Key);

		eng.Initialize(true, k);

		for (unsigned int i = 0; i != Count; i++)
			eng.Transform(outBytes, outBytes);

		if (outBytes != Output)
			throw TestException("Serpent MonteCarlo: Arrays are not equal!");
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

		SHX eng;
		Key::Symmetric::SymmetricKey k(key);

		eng.Initialize(true, k);
		eng.EncryptBlock(inBytes, outBytes);

		eng.Initialize(false, k);
		eng.DecryptBlock(outBytes, decBytes);

		if (inBytes != decBytes)
			throw TestException("Serpent: Decrypted arrays are not equal!");
	}

	void SerpentTest::CompareVector(std::vector<byte> &Key, std::vector<byte> &Input, std::vector<byte> &Output)
	{
		std::vector<byte> expBytes(16, 0);
		std::vector<byte> outBytes(16, 0);
		std::vector<byte> inBytes(16, 0);
		memcpy(&inBytes[0], &Input[0], 16);

		SHX enc;
		Key::Symmetric::SymmetricKey k(Key);
		enc.Initialize(true, k);
		enc.EncryptBlock(inBytes, outBytes);

		if (Output != outBytes)
			throw TestException("Serpent Vector: Arrays are not equal!");

		//TestUtils::Reverse(outBytes);
		SHX dec;
		dec.Initialize(false, k);
		dec.DecryptBlock(outBytes, expBytes);

		if (Input != expBytes)
			throw TestException("Serpent Vector: Arrays are not equal!");
	}

	void SerpentTest::OnProgress(std::string Data)
	{
		m_progressEvent(Data);
	}
}