#include "HKDSTest.h"
#include "../CEX/CryptoKmsException.h"
#include "../CEX/DUKPTClient.h"
#include "../CEX/DUKPTServer.h"
#include "../CEX/HKDSClient.h"
#include "../CEX/HKDSServer.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include <cstdio>
#include <ctime>

namespace Test
{
	typedef std::chrono::high_resolution_clock hrclock;
	typedef std::chrono::steady_clock::time_point ptime;

	using namespace KeyManagement;
	using Exception::CryptoKmsException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Prng::SecureRandom;

	const std::string HKDSTest::CLASSNAME = "HKDSTest";
	const std::string HKDSTest::DESCRIPTION = "HKDS 128/256 test vectors.";
	const std::string HKDSTest::SUCCESS = "SUCCESS! All HKDS tests have executed succesfully.";

	HKDSTest::HKDSTest()
		:
		m_expected(0),
		m_key(0),
		m_montecarlo(0),
		m_progressEvent()
	{
	}

	HKDSTest::~HKDSTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_montecarlo);
	}

	const std::string HKDSTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler& HKDSTest::Progress()
	{
		return m_progressEvent;
	}

	std::string HKDSTest::Run()
	{
		Initialize();

		try
		{
			Authentication(ShakeModes::SHAKE128);
			Authentication(ShakeModes::SHAKE256);
			Authentication(ShakeModes::SHAKE512);
			OnProgress(std::string("HKDSTest: Passed HKDS-128, HKDS-256, and HKDS-512 authentication tests.."));

			BenchmarkDecrypt();
			OnProgress(std::string("HKDSTest: Completed HKDS versus DUKPT server decryption benchmark comparison.."));
			BenchmarkDecryptVerify();
			OnProgress(std::string("HKDSTest: Completed HKDS versus DUKPT server authenticated decryption benchmark comparison.."));
			BenchmarkEncrypt();
			OnProgress(std::string("HKDSTest: Completed HKDS versus DUKPT server encryption benchmark comparison.."));
			BenchmarkEncryptAuthenticate();
			OnProgress(std::string("HKDSTest: Completed HKDS versus DUKPT client authenticated encryption benchmark comparison.."));

			Exception();
			OnProgress(std::string("HKDSTest: Passed HKDS exception handling tests.."));

			// standard encryption
			Kat(ShakeModes::SHAKE128, m_key[0], m_expected[0]);
			Kat(ShakeModes::SHAKE256, m_key[1], m_expected[1]);
			Kat(ShakeModes::SHAKE512, m_key[2], m_expected[2]);
			// authenticated encryption
			KatAE(ShakeModes::SHAKE128, m_key[0], m_expected[3]);
			KatAE(ShakeModes::SHAKE256, m_key[1], m_expected[4]);
			KatAE(ShakeModes::SHAKE512, m_key[2], m_expected[5]);
			OnProgress(std::string("HKDSTest: Passed HKDS known answer tests.."));

			MonteCarlo(ShakeModes::SHAKE128, m_key[0], m_montecarlo[0]);
			MonteCarlo(ShakeModes::SHAKE256, m_key[1], m_montecarlo[1]);
			MonteCarlo(ShakeModes::SHAKE512, m_key[2], m_montecarlo[2]);
			OnProgress(std::string("HKDSTest: Passed HKDS-128, HKDS-256, and HKDS-512 monte carlo KAT tests.."));

			Cycle(ShakeModes::SHAKE128);
			Cycle(ShakeModes::SHAKE256);
			Cycle(ShakeModes::SHAKE512);
			OnProgress(std::string("HKDSTest: Passed HKDS-128, HKDS-256, and HKDS-512 cycle tests.."));

			Stress();
			OnProgress(std::string("HKDSTest: Passed stress tests.."));

			return SUCCESS;
		}
		catch (TestException const& ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoKmsException & ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (CryptoException & ex)
		{
			throw TestException(CLASSNAME, ex.Location() + std::string("::") + ex.Origin(), ex.Name(), ex.Message());
		}
		catch (std::exception const& ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void HKDSTest::Authentication(ShakeModes Mode)
	{
		// the PRF mode
		const byte MODE = static_cast<byte>(Mode);
		// protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication
		const byte PID = 0x11;
		std::vector<byte> ad{ 0xC0, 0xA8, 0x00, 0x01 };
		std::vector<byte> cpt;
		std::vector<byte> dec;
		std::vector<byte> dk(0);
		std::vector<byte> etok(0);
		std::vector<byte> dtok(0);
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		// master key id
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		// device id		        |		BKD ID		  | PID | Mode |	MID	  |			DID			|
		const std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, PID, MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };

		// generate the master derivation key {BDK, BTK, KID}
		HKDSMasterKey mdk;
		HKDSServer::GenerateMdk(Mode, mdk, kid);

		// generate the clients embedded key
		dk = HKDSServer::GenerateEdk(mdk.BDK, did);

		// initialize the client
		HKDSClient clt(dk, did);

		// initialize the server with the client-ksn
		HKDSServer srv(mdk, clt.KSN());

		// client requests the token key from server
		etok = srv.EncryptToken();

		// client decrypts the token
		dtok = clt.DecryptToken(etok);

		// client derives the transaction key-set
		clt.GenerateKeyCache(dtok);

		// client encrypts a message
		cpt = clt.EncryptAuthenticate(msg, ad);

		try
		{
			// server decrypts the message
			dec = srv.DecryptVerify(cpt, ad);
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Authentication"), std::string("HKDS"), std::string("Authentication failure! -HC1"));
		}
		catch (CryptoKmsException const&)
		{
			throw TestException(std::string("Authentication"), std::string("HKDS"), std::string("Invalid ciphertext! -HC2"));
		}

		if (msg != dec)
		{
			throw TestException(std::string("Authentication"), std::string("HKDS"), std::string("The messages are not equal! -HC3"));
		}
	}

	void HKDSTest::BenchmarkDecrypt()
	{
		// the PRF modes
		const byte MODE128 = static_cast<byte>(ShakeModes::SHAKE128);
		const byte MODE256 = static_cast<byte>(ShakeModes::SHAKE256);
		// protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication
		const byte PID = 0x10;
		const size_t MAXLOOP = 1000;
		std::vector<byte> dbdk128;
		std::vector<byte> dbdk256;
		std::vector<byte> dec(16);
		std::vector<byte> dksn{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> hksn128{ 0x01, 0x02, 0x03, 0x04, PID, MODE128, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00 };
		std::vector<byte> hksn256{ 0x01, 0x02, 0x03, 0x04, PID, MODE256, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00 };
		std::vector<byte> ikid;
		std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		ulong duration;
		ulong total;
		uint i;
		uint j;
		uint tctr;

		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk128);
		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk256);
		HexConverter::Decode("1234567890123456", ikid);
		MemoryTools::Copy(ikid, 0, dksn, 0, ikid.size());

		// 128-bit comparison

		DUKPTServer dsrv;

		HKDSMasterKey mdk128;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk128, kid);
		HKDSServer hsrv128(mdk128, hksn128);
		const size_t MAXITR128 = hsrv128.KeyCacheSize();

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR128) + j;
				IntegerTools::Be32ToBytes(tctr, dksn, 8);
				ptime t1 = hrclock::now();
				dec = dsrv.Decrypt(dbdk128, dksn, msg);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-128: Server decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;
			// added for accurate timing measurement
			hsrv128.EncryptToken();

			for (j = 0; j < MAXITR128; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR128) + j;
				IntegerTools::Le32ToBytes(tctr, hksn128, 12);
				ptime t1 = hrclock::now();
				if (j == 0)
				{
					// added for accurate timing measurement of a complete cycle
					hsrv128.EncryptToken();
				}
				hsrv128.Decrypt(msg, dec);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-128: Server decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		// 256-bit comparison

		total = 0;

		HKDSMasterKey mdk256;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE256, mdk256, kid);
		HKDSServer hsrv256(mdk256, hksn256);
		const size_t MAXITR256 = hsrv256.KeyCacheSize();

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR256) + j;
				IntegerTools::Be32ToBytes(tctr, dksn, 8);
				auto t1 = hrclock::now();
				dec = dsrv.Decrypt(dbdk256, dksn, msg);
				auto t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-256: Server decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR256) + j;
				IntegerTools::Le32ToBytes(tctr, hksn256, 12);
				auto t1 = hrclock::now();
				if (j == 0)
				{
					// added for accurate timing measurement of a complete cycle
					hsrv256.EncryptToken();
				}
				hsrv256.Decrypt(msg, dec);
				auto t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-256: Server decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));
	}

	void HKDSTest::BenchmarkDecryptVerify()
	{
		const size_t MAXLOOP = 1000;
		std::vector<byte> ad(0);
		std::vector<byte> cpt;
		std::vector<byte> dbdk128;
		std::vector<byte> dbdk256;
		std::vector<byte> dec;
		const std::vector<byte> did128{ 0x01, 0x00, 0x00, 0x00, 0xD1, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		const std::vector<byte> did256{ 0x01, 0x00, 0x00, 0x00, 0xD1, 0x0A, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> dinitid(0);
		std::vector<byte> dk(0);
		std::vector<byte> dkey128(0);
		std::vector<byte> dkey256(0);
		std::vector<byte> dksn{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> dtok;
		std::vector<byte> etok;
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		ulong duration;
		ulong total;
		uint i;
		uint j;
		uint tctr;

		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk128);
		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk256);
		HexConverter::Decode("1273671EA26AC29AFA4D1084127652A1", dkey128);
		HexConverter::Decode("CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F", dkey256);
		HexConverter::Decode("1234567890123456", dinitid);

		total = 0;
		HKDSMasterKey mdk128;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk128, kid);
		dk = HKDSServer::GenerateEdk(mdk128.BDK, did128);
		HKDSClient hclt128(dk, did128);
		HKDSServer hsrv128(mdk128, hclt128.KSN());

		// authenticated encryption uses 2 keys, not one, for both DUKPT and HKDS
		const size_t MAXITR128 = hsrv128.KeyCacheSize() / 2;

		DUKPTServer dsrv128;
		// initialize the client
		DUKPTClient dclt128;
		dclt128.LoadInitialKey(dkey128, DukptKeyType::AES128, dinitid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(dinitid, 0, dksn, 0, dinitid.size());

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR128) + j;
				IntegerTools::Be32ToBytes(dclt128.TransactionCounter(), dksn, dinitid.size());
				cpt = dclt128.EncryptAuthenticate(msg, ad);
				ptime t1 = hrclock::now();
				msg = dsrv128.DecryptVerify(dbdk128, dksn, cpt, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-128: Server authenticated decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				hsrv128.KSN() = hclt128.KSN();

				if (j == 0)
				{
					etok = hsrv128.EncryptToken();
					dtok = hclt128.DecryptToken(etok);
					hclt128.GenerateKeyCache(dtok);
				}

				cpt = hclt128.EncryptAuthenticate(msg, ad);

				ptime t1 = hrclock::now();
				dec = hsrv128.DecryptVerify(cpt, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-128: Server authenticated decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		// 256-bit

		DUKPTServer dsrv256;
		// initialize the client
		DUKPTClient dclt256;
		dclt256.LoadInitialKey(dkey256, DukptKeyType::AES256, dinitid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(dinitid, 0, dksn, 0, dinitid.size());

		HKDSMasterKey mdk256;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk256, kid);
		dk = HKDSServer::GenerateEdk(mdk256.BDK, did256);
		HKDSClient hclt256(dk, did256);
		HKDSServer hsrv256(mdk256, hclt256.KSN());

		// authenticated encryption uses 2 keys, not one, for both DUKPT and HKDS
		const size_t MAXITR256 = hsrv256.KeyCacheSize() / 2;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR256) + j;
				IntegerTools::Be32ToBytes(dclt256.TransactionCounter(), dksn, dinitid.size());
				cpt = dclt256.EncryptAuthenticate(msg, ad);
				ptime t1 = hrclock::now();
				msg = dsrv256.DecryptVerify(dbdk256, dksn, cpt, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-256: Server authenticated decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				hsrv256.KSN() = hclt256.KSN();

				if (j == 0)
				{
					etok = hsrv256.EncryptToken();
					dtok = hclt256.DecryptToken(etok);
					hclt256.GenerateKeyCache(dtok);
				}

				cpt = hclt256.EncryptAuthenticate(msg, ad);	

				ptime t1 = hrclock::now();
				dec = hsrv256.DecryptVerify(cpt, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-256: Server authenticated decryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));
	}

	void HKDSTest::BenchmarkEncrypt()
	{
		const size_t MAXLOOP = 1000;
		std::vector<byte> ad(0);
		std::vector<byte> cpt;
		std::vector<byte> dbdk128;
		std::vector<byte> dbdk256;
		const std::vector<byte> did128{ 0x01, 0x00, 0x00, 0x00, 0xD1, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		const std::vector<byte> did256{ 0x01, 0x00, 0x00, 0x00, 0xD1, 0x0A, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> dinitid(0);
		std::vector<byte> dk(0);
		std::vector<byte> dkey128(0);
		std::vector<byte> dkey256(0);
		std::vector<byte> dksn{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> dtok;
		std::vector<byte> etok;
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		ulong duration;
		ulong total;
		uint i;
		uint j;
		uint tctr;

		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk128);
		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk256);
		HexConverter::Decode("1273671EA26AC29AFA4D1084127652A1", dkey128);
		HexConverter::Decode("CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F", dkey256);
		HexConverter::Decode("1234567890123456", dinitid);

		total = 0;
		HKDSMasterKey mdk128;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk128, kid);
		dk = HKDSServer::GenerateEdk(mdk128.BDK, did128);
		HKDSClient hclt128(dk, did128);
		HKDSServer hsrv128(mdk128, hclt128.KSN());

		const size_t MAXITR128 = hsrv128.KeyCacheSize();

		DUKPTServer dsrv128;
		// initialize the client
		DUKPTClient dclt128;
		dclt128.LoadInitialKey(dkey128, DukptKeyType::AES128, dinitid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(dinitid, 0, dksn, 0, dinitid.size());

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR128) + j;
				IntegerTools::Be32ToBytes(dclt128.TransactionCounter(), dksn, dinitid.size());
				ptime t1 = hrclock::now();
				cpt = dclt128.Encrypt(msg);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-128: Client encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				if (j == 0)
				{
					etok = hsrv128.EncryptToken();
					dtok = hclt128.DecryptToken(etok);
					hclt128.GenerateKeyCache(dtok);
				}

				hsrv128.KSN() = hclt128.KSN();

				ptime t1 = hrclock::now();
				hclt128.Encrypt(msg, cpt);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-128: Client encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		// 256-bit

		DUKPTServer dsrv256;
		// initialize the client
		DUKPTClient dclt256;
		dclt256.LoadInitialKey(dkey256, DukptKeyType::AES256, dinitid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(dinitid, 0, dksn, 0, dinitid.size());

		HKDSMasterKey mdk256;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk256, kid);
		dk = HKDSServer::GenerateEdk(mdk256.BDK, did256);
		HKDSClient hclt256(dk, did256);
		HKDSServer hsrv256(mdk256, hclt256.KSN());

		const size_t MAXITR256 = hsrv256.KeyCacheSize();

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR256) + j;
				IntegerTools::Be32ToBytes(dclt256.TransactionCounter(), dksn, dinitid.size());
				ptime t1 = hrclock::now();
				cpt = dclt256.Encrypt(msg);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-256: Client encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				if (j == 0)
				{
					etok = hsrv256.EncryptToken();
					dtok = hclt256.DecryptToken(etok);
					hclt256.GenerateKeyCache(dtok);
				}

				hsrv256.KSN() = hclt256.KSN();
				ptime t1 = hrclock::now();
				hclt256.Encrypt(msg, cpt);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-256: Client encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));
	}

	void HKDSTest::BenchmarkEncryptAuthenticate()
	{
		const size_t MAXLOOP = 1000;
		std::vector<byte> ad(0);
		std::vector<byte> cpt;
		std::vector<byte> dbdk128;
		std::vector<byte> dbdk256;
		const std::vector<byte> did128{ 0x01, 0x00, 0x00, 0x00, 0xD1, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		const std::vector<byte> did256{ 0x01, 0x00, 0x00, 0x00, 0xD1, 0x0A, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> dinitid(0);
		std::vector<byte> dk(0);
		std::vector<byte> dkey128(0);
		std::vector<byte> dkey256(0);
		std::vector<byte> dksn{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x00, 0x00, 0x00 };
		std::vector<byte> dtok;
		std::vector<byte> etok;
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		ulong duration;
		ulong total;
		uint i;
		uint j;
		uint tctr;

		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk128);
		HexConverter::Decode("FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1", dbdk256);
		HexConverter::Decode("1273671EA26AC29AFA4D1084127652A1", dkey128);
		HexConverter::Decode("CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F", dkey256);
		HexConverter::Decode("1234567890123456", dinitid);

		total = 0;
		HKDSMasterKey mdk128;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk128, kid);
		dk = HKDSServer::GenerateEdk(mdk128.BDK, did128);
		HKDSClient hclt128(dk, did128);
		HKDSServer hsrv128(mdk128, hclt128.KSN());

		// authenticated encryption uses 2 keys, not one, for both DUKPT and HKDS
		const size_t MAXITR128 = hsrv128.KeyCacheSize() / 2;

		DUKPTServer dsrv128;
		// initialize the client
		DUKPTClient dclt128;
		dclt128.LoadInitialKey(dkey128, DukptKeyType::AES128, dinitid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(dinitid, 0, dksn, 0, dinitid.size());

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR128) + j;
				IntegerTools::Be32ToBytes(dclt128.TransactionCounter(), dksn, dinitid.size());
				ptime t1 = hrclock::now();
				cpt = dclt128.EncryptAuthenticate(msg, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-128: Client authenticated encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR128; ++j)
			{
				hsrv128.KSN() = hclt128.KSN();

				if (j == 0)
				{
					etok = hsrv128.EncryptToken();
					dtok = hclt128.DecryptToken(etok);
					hclt128.GenerateKeyCache(dtok);
				}

				ptime t1 = hrclock::now();
				cpt = hclt128.EncryptAuthenticate(msg, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR128;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-128: Client authenticated encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR128) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		// 256-bit

		DUKPTServer dsrv256;
		// initialize the client
		DUKPTClient dclt256;
		dclt256.LoadInitialKey(dkey256, DukptKeyType::AES256, dinitid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(dinitid, 0, dksn, 0, dinitid.size());

		HKDSMasterKey mdk256;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE128, mdk256, kid);
		dk = HKDSServer::GenerateEdk(mdk256.BDK, did256);
		HKDSClient hclt256(dk, did256);
		HKDSServer hsrv256(mdk256, hclt256.KSN());

		// authenticated encryption uses 2 keys, not one, for both DUKPT and HKDS
		const size_t MAXITR256 = hsrv256.KeyCacheSize() / 2;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				tctr = static_cast<uint>(i * MAXITR256) + j;
				IntegerTools::Be32ToBytes(dclt256.TransactionCounter(), dksn, dinitid.size());
				ptime t1 = hrclock::now();
				cpt = dclt256.EncryptAuthenticate(msg, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("DUKPT-256: Client authenticated encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));

		total = 0;

		for (i = 0; i < MAXLOOP; ++i)
		{
			duration = 0;

			for (j = 0; j < MAXITR256; ++j)
			{
				hsrv256.KSN() = hclt256.KSN();

				if (j == 0)
				{
					etok = hsrv256.EncryptToken();
					dtok = hclt256.DecryptToken(etok);
					hclt256.GenerateKeyCache(dtok);
				}

				ptime t1 = hrclock::now();
				cpt = hclt256.EncryptAuthenticate(msg, ad);
				ptime t2 = hrclock::now();
				duration += std::chrono::duration_cast<std::chrono::nanoseconds>(t2 - t1).count();
			}

			duration /= MAXITR256;
			total += duration;
		}

		total /= MAXLOOP;
		OnProgress("HKDS-256: Client authenticated encryption; average nanoseconds from " + IntegerTools::ToString(MAXITR256) + " thousand transactions");
		OnProgress(IntegerTools::ToString(total));
	}

	void HKDSTest::Cycle(ShakeModes ShakeMode)
	{
		// the PRF mode
		const byte MODE = static_cast<byte>(ShakeMode);
		const byte PID = 0x10;
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		std::vector<byte> cpt(16);
		std::vector<byte> dec(16);
		std::vector<byte> dk(0);
		std::vector<byte> etok(0);
		std::vector<byte> dtok(0);
		// master key id
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		// device id		        |		BKD ID		  | PID | Mode |	MID	  |			DID			|
		const std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, PID, MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };

		// generate the master derivation key {BDK, BTK, KID}
		HKDSMasterKey mdk;
		HKDSServer::GenerateMdk(ShakeMode, mdk, kid);

		// generate the clients embedded key
		dk = HKDSServer::GenerateEdk(mdk.BDK, did);

		// initialize the client
		HKDSClient clt(dk, did);

		// initialize the server with the client-ksn
		HKDSServer srv(mdk, clt.KSN());

		// client requests the token key from server
		etok = srv.EncryptToken();

		// client decrypts the token
		dtok = clt.DecryptToken(etok);

		// client derives the transaction key-set
		clt.GenerateKeyCache(dtok);

		// client encrypts a message
		clt.Encrypt(msg, cpt);

		// server decrypts the message
		srv.Decrypt(cpt, dec);

		if (msg != dec)
		{
			throw TestException(std::string("Cycle"), std::string(""), std::string("The messages are not equal! -HC1"));
		}
	}

	void HKDSTest::Exception()
	{
		// test invalid message size

		try
		{
			// invalid message size
			std::vector<byte> cpt(16);
			std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
			std::vector<byte> ksn = { 0x01, 0x00, 0x00, 0x00, 0xFF, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			std::vector<byte> msg(15);
			HKDSMasterKey mdk;
			HKDSServer::GenerateMdk(ShakeModes::SHAKE256, mdk, kid);
			HKDSServer srv(mdk, ksn);

			srv.Decrypt(cpt, msg);

			throw TestException(std::string("Exception"), std::string("HKDS"), std::string("Exception handling failure! -HE1"));
		}
		catch (CryptoKmsException const&)
		{
		}
		catch (TestException const&)
		{
			throw;
		}

		// test invalid ciphertext size

		try
		{
			std::vector<byte> ad(0);
			// invalid message size
			std::vector<byte> cpt(31);
			std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
			std::vector<byte> ksn = { 0x01, 0x00, 0x00, 0x00, 0xFF, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			std::vector<byte> msg(16);
			HKDSMasterKey mdk;
			HKDSServer::GenerateMdk(ShakeModes::SHAKE256, mdk, kid);
			HKDSServer srv(mdk, ksn);

			msg = srv.DecryptVerify(cpt, ad);

			throw TestException(std::string("Exception"), std::string("HKDS"), std::string("Exception handling failure! -HE2"));
		}
		catch (CryptoKmsException const&)
		{
		}
		catch (TestException const&)
		{
			throw;
		}

		// test authentication check

		try
		{
			std::vector<byte> ad(0);
			std::vector<byte> cpt(32);
			std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, 0xFF, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
			std::vector<byte> dk;
			std::vector<byte> dtok;
			std::vector<byte> etok;
			std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
			std::vector<byte> ksn = { 0x01, 0x00, 0x00, 0x00, 0xFF, 0x09, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			std::vector<byte> msg(16);
			HKDSMasterKey mdk;
			HKDSServer::GenerateMdk(ShakeModes::SHAKE256, mdk, kid);

			// generate the clients embedded key
			dk = HKDSServer::GenerateEdk(mdk.BDK, did);
			HKDSServer srv(mdk, ksn);
			// client requests the token key from server
			etok = srv.EncryptToken();

			// initialize the client
			HKDSClient clt(dk, did);
			// client decrypts the token
			dtok = clt.DecryptToken(etok);
			// client derives the transaction key-set
			clt.GenerateKeyCache(dtok);
			// client encrypts a message
			cpt = clt.EncryptAuthenticate(msg, ad);

			// change ciphertext
			++cpt[0];
			msg = srv.DecryptVerify(cpt, ad);

			throw TestException(std::string("Exception"), std::string("HKDS"), std::string("Exception handling failure! -HE4"));
		}
		catch (CryptoAuthenticationFailure const&)
		{
		}
		catch (TestException const&)
		{
			throw;
		}
	}

	void HKDSTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */
		const std::vector<std::string> keys =
		{
			std::string("000102030405060708090A0B0C0D0E0F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"),
			std::string("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
				"202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F")
		};
		HexConverter::Decode(keys, 3, m_key);

		const std::vector<std::string> expected =
		{
			// official vectors
			// standard encryption: SHAKE-128
			std::string("21EDC540F713649F38EDB3CB9E26336E"),
			// SHAKE-256
			std::string("4422FD14DC32CF52765227782B7DF346"),
			// SHAKE-512
			std::string("8F8237E723C13AC5C07BDDE483F586DB"),
			// authenticated encryption: SHAKE-128
			std::string("A0BFAB1B05D8005B0F8929A0DDF5BEF6510E048375C715319C3CCE6FA29D3C8F"),
			// SHAKE-256
			std::string("11A91FAE7C8019CF273EE74AB544631F0B3C56745578192379CD649EE591D488"),
			// SHAKE-512
			std::string("0D818095417A9AA6DB9555B491348F3C8513E6196A67EC992719B324E5F2E58B")
		};
		HexConverter::Decode(expected, 6, m_expected);
		
		const std::vector<std::string> montecarlo =
		{
			std::string("A2968FF59E0D700AD418EB0387D9F5E7"),
			std::string("5DA79EFD4C52DA29E08D14E05771130D"),
			std::string("84827779CF9765C50DED4582B8384324")
		};
		HexConverter::Decode(montecarlo, 3, m_montecarlo);

		/*lint -restore */
	}

	void HKDSTest::Kat(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Expected)
	{
		// the PRF mode
		const byte MODE = static_cast<byte>(ShakeMode);
		// protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication
		const byte PID = 0x10;
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		std::vector<byte> cpt(16);
		std::vector<byte> dec(16);
		std::vector<byte> dk;
		std::vector<byte> etok;
		std::vector<byte> dtok;
		// master key id
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		// device id				|		BKD ID		  | PID | Mode |	MID	  |			DID			|
		const std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, PID, MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };

		// test master-key with known values
		HKDSMasterKey mdk;
		mdk.BDK.resize(Key.size());
		mdk.STK.resize(Key.size());
		mdk.KID.resize(kid.size());
		MemoryTools::Copy(Key, 0, mdk.BDK, 0, Key.size());
		MemoryTools::Copy(Key, 0, mdk.STK, 0, Key.size());
		MemoryTools::Copy(kid, 0, mdk.KID, 0, kid.size());

		// generate the clients embedded key
		dk = HKDSServer::GenerateEdk(mdk.BDK, did);

		// initialize the client
		HKDSClient clt(dk, did);

		// initialize the server with the client-ksn
		HKDSServer srv(mdk, clt.KSN());

		// client requests the token key from server
		etok = srv.EncryptToken();

		// client decrypts the token
		dtok = clt.DecryptToken(etok);

		// client derives the transaction key-set
		clt.GenerateKeyCache(dtok);

		// client encrypts a message
		clt.Encrypt(msg, cpt);

		if (cpt != Expected)
		{
			throw TestException(std::string("Kat"), std::string("HKDS"), std::string("Output does not match the known answer! -HK1"));
		}

		// server decrypts the message
		srv.Decrypt(cpt, dec);

		if (msg != dec)
		{
			throw TestException(std::string("Kat"), std::string("HKDS"), std::string("The messages are not equal! -HK2"));
		}
	}

	void HKDSTest::KatAE(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Expected)
	{
		// the PRF mode
		const byte MODE = static_cast<byte>(ShakeMode);
		// protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication
		const byte PID = 0x11;
		std::vector<byte> ad{ 0xC0, 0xA8, 0x00, 0x01 };
		std::vector<byte> cpt;
		std::vector<byte> dec;
		std::vector<byte> dk;
		std::vector<byte> etok;
		std::vector<byte> dtok;
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		// master key id
		const std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		// device id				|		BKD ID		  | PID | Mode |	MID	  |			DID			|
		const std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, PID, MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };

		// test master-key with known values
		HKDSMasterKey mdk;
		mdk.BDK.resize(Key.size());
		mdk.STK.resize(Key.size());
		mdk.KID.resize(kid.size());
		MemoryTools::Copy(Key, 0, mdk.BDK, 0, Key.size());
		MemoryTools::Copy(Key, 0, mdk.STK, 0, Key.size());
		MemoryTools::Copy(kid, 0, mdk.KID, 0, kid.size());

		// generate the clients embedded key
		dk = HKDSServer::GenerateEdk(mdk.BDK, did);

		// initialize the client
		HKDSClient clt(dk, did);

		// initialize the server with the client-ksn
		HKDSServer srv(mdk, clt.KSN());

		// client requests the token key from server
		etok = srv.EncryptToken();

		// client decrypts the token
		dtok = clt.DecryptToken(etok);

		// client derives the transaction key-set
		clt.GenerateKeyCache(dtok);

		// client encrypts a message
		cpt = clt.EncryptAuthenticate(msg, ad);

		if (cpt != Expected)
		{
			throw TestException(std::string("KatAE"), std::string("HKDS"), std::string("Output does not match the known answer! -HK1"));
		}

		try
		{
			// server decrypts the message
			dec = srv.DecryptVerify(cpt, ad);
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("KatAE"), std::string("HKDS"), std::string("Authentication failure! -HK2"));
		}

		if (msg != dec)
		{
			throw TestException(std::string("KatAE"), std::string("HKDS"), std::string("The messages are not equal! -HK3"));
		}
	}

	void HKDSTest::MonteCarlo(ShakeModes ShakeMode, const std::vector<byte> &Key, const std::vector<byte> &Expected)
	{	// the PRF mode
		const byte MODE = static_cast<byte>(ShakeMode);
		// protocol id is always 0x10 for unauthenticated HKDS, 0x11 for KMAC authentication
		const byte PID = 0x10;
		std::vector<byte> mres(16);
		std::vector<byte> msg(16);
		std::vector<byte> cpt(16);
		std::vector<byte> dec(16);
		std::vector<byte> dk;
		std::vector<byte> etok;
		std::vector<byte> dtok;
		// master key id
		std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		// device id		   |		BKD ID		  | PID | Mode |	MID	  |			DID			|
		std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, PID, MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		SecureRandom rnd;
		size_t i;

		rnd.Generate(msg);

		// generate the master derivation key {BDK, BTK, MID}
		// test master-key with known values
		HKDSMasterKey mdk;
		mdk.BDK.resize(Key.size());
		mdk.STK.resize(Key.size());
		mdk.KID.resize(kid.size());
		MemoryTools::Copy(Key, 0, mdk.BDK, 0, Key.size());
		MemoryTools::Copy(Key, 0, mdk.STK, 0, Key.size());
		MemoryTools::Copy(kid, 0, mdk.KID, 0, kid.size());


		// generate the clients embedded key
		dk = HKDSServer::GenerateEdk(mdk.BDK, did);

		// initialize the client with its device id and embedded key
		HKDSClient clt(dk, did);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			// initialize the server with the client-ksn and corresponding master key
			HKDSServer srv(mdk, clt.KSN());

			if (clt.KeyCount() == 0)
			{
				// client requests the token key from server
				etok = srv.EncryptToken();

				// client decrypts the token
				dtok = clt.DecryptToken(etok);

				// client derives the transaction key-set
				clt.GenerateKeyCache(dtok);
			}

			// client encrypts a message
			clt.Encrypt(msg, cpt);

			// server decrypts the message
			srv.Decrypt(cpt, dec);

			if (msg != dec)
			{
				throw TestException(std::string("MonteCarlo"), std::string("HKDS"), std::string("The messages are not equal! -HM1"));
			}

			MemoryTools::XOR(cpt, 0, mres, 0, mres.size());
		}

		if (mres != Expected)
		{
			throw TestException(std::string("MonteCarlo"), std::string("HKDS"), std::string("The messages are not equal! -HM2"));
		}
	}

	void HKDSTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void HKDSTest::Stress()
	{
		// the PRF mode
		const byte MODE = static_cast<byte>(ShakeModes::SHAKE256);
		// protocol id is always 0xFF for HKDS
		const byte PID = 0xFF;
		std::vector<byte> msg(16);
		std::vector<byte> cpt(16);
		std::vector<byte> dec(16);
		std::vector<byte> dk;
		std::vector<byte> etok;
		std::vector<byte> dtok;
		// master key id
		std::vector<byte> kid{ 0x01, 0x02, 0x03, 0x04 };
		// device id		   |		BKD ID		  | PID | Mode |	MID	  |			DID			|
		std::vector<byte> did{ 0x01, 0x00, 0x00, 0x00, PID, MODE, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 };
		SecureRandom rnd;
		size_t i;

		rnd.Generate(msg);

		// generate the master derivation key {BDK, BTK, MID}
		HKDSMasterKey mdk;
		HKDSServer::GenerateMdk(ShakeModes::SHAKE256, mdk, kid);

		// generate the clients embedded key
		dk = HKDSServer::GenerateEdk(mdk.BDK, did);

		// initialize the client with its device id and embedded key
		HKDSClient clt(dk, did);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			// initialize the server with the client-ksn and corresponding master key
			HKDSServer srv(mdk, clt.KSN());

			if (clt.KeyCount() == 0)
			{
				// client requests the token key from server
				etok = srv.EncryptToken();

				// client decrypts the token
				dtok = clt.DecryptToken(etok);

				// client derives the transaction key-set
				clt.GenerateKeyCache(dtok);
			}

			// client encrypts a message
			clt.Encrypt(msg, cpt);

			// server decrypts the message
			srv.Decrypt(cpt, dec);

			if (msg != dec)
			{
				throw TestException(std::string("Stress"), std::string("HKDS"), std::string("The messages are not equal! -HS1"));
			}
		}
	}
}
