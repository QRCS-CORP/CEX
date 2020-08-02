#include "DUKPTTest.h"
#include "../CEX/CryptoKmsException.h"
#include "../CEX/DUKPTClient.h"
#include "../CEX/DUKPTServer.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"

namespace Test
{
	using namespace KeyManagement;
	using Exception::CryptoKmsException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Prng::SecureRandom;

	const std::string DUKPTTest::CLASSNAME = "DUKPTTest";
	const std::string DUKPTTest::DESCRIPTION = "DUKPT AES-128/256 test vectors.";
	const std::string DUKPTTest::SUCCESS = "SUCCESS! All DUKPT tests have executed succesfully.";

	DUKPTTest::DUKPTTest()
		:
		m_bdk(0),
		m_derivationdata(0),
		m_derivationkey(0),
		m_workingKey(0),
		m_initialkey(0),
		m_initialkeyid(0),
		m_progressEvent()
	{
	}

	DUKPTTest::~DUKPTTest()
	{
		size_t i;

		for (i = 0; i < m_bdk.size(); ++i)
		{
			IntegerTools::Clear(m_bdk[i]);
		}

		for (i = 0; i < m_derivationdata.size(); ++i)
		{
			IntegerTools::Clear(m_derivationdata);
		}

		for (i = 0; i < m_derivationkey.size(); ++i)
		{
			IntegerTools::Clear(m_derivationkey);
		}

		for (i = 0; i < m_workingKey.size(); ++i)
		{
			IntegerTools::Clear(m_workingKey);
		}

		IntegerTools::Clear(m_initialkey);
		IntegerTools::Clear(m_initialkeyid);
	}

	const std::string DUKPTTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler& DUKPTTest::Progress()
	{
		return m_progressEvent;
	}

	std::string DUKPTTest::Run()
	{
		Initialize();

		try
		{
			Authentication(DukptKeyType::AES128);
			Authentication(DukptKeyType::AES256);
			OnProgress(std::string("DUKPTTest: Passed DUKPT-128 and HKDS-256 authentication tests.."));

			Exception();
			OnProgress(std::string("DUKPTTest: Passed DUKPT exception handling tests.."));

			// aes-128 
			Kat(m_bdk[0], 1, m_derivationkey[0], m_derivationdata[0], m_workingKey[0]);
			Kat(m_bdk[0], 2, m_derivationkey[1], m_derivationdata[1], m_workingKey[1]);
			Kat(m_bdk[0], 3, m_derivationkey[2], m_derivationdata[2], m_workingKey[2]);
			Kat(m_bdk[0], 4294852608, m_derivationkey[3], m_derivationdata[3], m_workingKey[3]);
			Kat(m_bdk[0], 4294868992, m_derivationkey[4], m_derivationdata[4], m_workingKey[4]);
			Kat(m_bdk[0], 4294901760, m_derivationkey[5], m_derivationdata[5], m_workingKey[5]);
			// aes-256
			Kat(m_bdk[1], 1, m_derivationkey[6], m_derivationdata[6], m_workingKey[6]);
			Kat(m_bdk[1], 2, m_derivationkey[7], m_derivationdata[7], m_workingKey[7]);
			Kat(m_bdk[1], 3, m_derivationkey[8], m_derivationdata[8], m_workingKey[8]);
			Kat(m_bdk[1], 4294852608, m_derivationkey[9], m_derivationdata[9], m_workingKey[9]);
			Kat(m_bdk[1], 4294868992, m_derivationkey[10], m_derivationdata[10], m_workingKey[10]);
			Kat(m_bdk[1], 4294901760, m_derivationkey[11], m_derivationdata[11], m_workingKey[11]);
			OnProgress(std::string("DUKPTTest: Passed DUKPT-AES known answer tests.."));

			Cycle(DukptKeyType::AES128);
			OnProgress(std::string("DUKPTTest: Passed DUKPT-128 cycle tests.."));
			Cycle(DukptKeyType::AES256);
			OnProgress(std::string("DUKPTTest: Passed DUKPT-256 cycle tests.."));

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

	void DUKPTTest::Authentication(DukptKeyType KeyType)
	{
		std::vector<byte> ad{ 0xC0, 0xA8, 0x00, 0x01 };
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		std::vector<byte> cpt;
		std::vector<byte> dec;
		std::vector<byte> kid(12, 0x00);
		const size_t KEYIDX = (KeyType == DukptKeyType::AES128) ? 0 : 1;
		size_t i;

		// initialize the client
		DUKPTClient clt;
		clt.LoadInitialKey(m_initialkey[KEYIDX], KeyType, m_initialkeyid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(m_initialkeyid, 0, kid, 0, m_initialkeyid.size());

		// initialize the server
		DUKPTServer srv;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			// get the current transaction counter and add to clients key-id
			IntegerTools::Be32ToBytes(clt.TransactionCounter(), kid, m_initialkeyid.size());

			// client encrypts the message and appends an authentication tag
			// an optional data can be added for authentication, like the clients IP address
			cpt = clt.EncryptAuthenticate(msg, ad);

			try
			{
				// check the message integrity, if it fails throw without decrypting
				dec = srv.DecryptVerify(m_bdk[KEYIDX], kid, cpt, ad);
			}
			catch (CryptoAuthenticationFailure const&)
			{
				throw TestException(std::string("Cycle"), std::string("DUKPT"), std::string("The message failed authentication! -KC1"));
			}
			catch (CryptoKmsException const&)
			{
				throw TestException(std::string("Cycle"), std::string("DUKPT"), std::string("The ciphertext is invalid! -KC2"));
			}

			if (msg != dec)
			{
				throw TestException(std::string("Cycle"), std::string("DUKPT"), std::string("The decrypted message is not equal! -KC3"));
			}
		}
	}

	void DUKPTTest::Cycle(DukptKeyType KeyType)
	{
		std::vector<byte> msg{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
		std::vector<byte> cpt;
		std::vector<byte> dec;
		std::vector<byte> ad(0);
		std::vector<byte> kid(12, 0x00);
		const size_t KEYIDX = (KeyType == DukptKeyType::AES128) ? 0 : 1;
		size_t i;

		// initialize the client
		DUKPTClient clt;
		clt.LoadInitialKey(m_initialkey[KEYIDX], KeyType, m_initialkeyid);
		// copy the intitial key id to the clients id string
		MemoryTools::Copy(m_initialkeyid, 0, kid, 0, m_initialkeyid.size());

		// initialize the server
		DUKPTServer srv;

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			// get the current transaction counter and add to clients key-id
			IntegerTools::Be32ToBytes(clt.TransactionCounter(), kid, m_initialkeyid.size());

			// client encrypts the message
			cpt = clt.Encrypt(msg);

			// server decrypts the plaintext
			dec = srv.Decrypt(m_bdk[KEYIDX], kid, cpt);

			if (msg != dec)
			{
				throw TestException(std::string("Cycle"), std::string("DUKPT"), std::string("The decrypted message is not equal! -KC3"));
			}
		}
	}

	void DUKPTTest::Exception()
	{
		// test basic decryption
		try
		{
			// invalid message size
			std::vector<byte> msg(15);
			DUKPTServer srv;

			srv.Decrypt(m_bdk[0], m_initialkeyid, msg);

			throw TestException(std::string("Exception"), std::string("DUKPT"), std::string("Exception handling failure! -HE1"));
		}
		catch (CryptoKmsException const&)
		{
		}
		catch (TestException const&)
		{
			throw;
		}

		// test verified decryption
		try
		{
			std::vector<byte> ad(0);
			// invalid authenticated ciphertext size
			std::vector<byte> cpt(47);
			std::vector<byte> msg;
			DUKPTServer srv;

			msg = srv.DecryptVerify(m_bdk[0], m_initialkeyid, cpt, ad);

			throw TestException(std::string("Exception"), std::string("DUKPT"), std::string("Exception handling failure! -HE2"));
		}
		catch (CryptoKmsException const&)
		{
		}
		catch (TestException const&)
		{
			throw;
		}

		// test verifification
		try
		{
			std::vector<byte> ad(0);
			// invalid authenticated ciphertext size
			std::vector<byte> cpt;
			std::vector<byte> kid(12, 0x00);
			std::vector<byte> msg(16, 0xFF);

			// initialize the client and encrypt and authenticate a pin
			DUKPTClient clt;
			clt.LoadInitialKey(m_initialkey[0], DukptKeyType::AES128, m_initialkeyid);
			MemoryTools::Copy(m_initialkeyid, 0, kid, 0, m_initialkeyid.size());
			IntegerTools::Be32ToBytes(clt.TransactionCounter(), kid, m_initialkeyid.size());
			cpt = clt.EncryptAuthenticate(msg, ad);

			// initialize the server
			DUKPTServer srv;

			// change the ciphertext
			cpt[0]++;

			msg = srv.DecryptVerify(m_bdk[0], kid, cpt, ad);

			// if it gets here, verification has malfunctioned
			throw TestException(std::string("Exception"), std::string("DUKPT"), std::string("Exception handling failure! -HE2"));
		}
		catch (CryptoAuthenticationFailure const&)
		{
		}
		catch (TestException const&)
		{
			throw;
		}
	}

	void DUKPTTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}

	void DUKPTTest::Kat(const std::vector<byte> &Bdk, uint Counter, const std::vector<byte> &Derived,
		const std::vector<byte> &Data, const std::vector<byte> &Working)
	{
		std::vector<byte> msg(16);
		std::vector<byte> dec(16);
		DukptKeyType ktype = Bdk.size() == 16 ? DukptKeyType::AES128 : DukptKeyType::AES256;

		DUKPTServer srv;
		DukptServerState state;

		srv.DeriveWorkingKey(state, Bdk, DukptKeyUsage::PINEncryption, ktype, m_initialkeyid, Counter);

		if (state.DerivationKey != Derived)
		{
			throw TestException(std::string("Kat"), std::string("DUKPT"), std::string("Output does not match the known answer! -HK1"));
		}

		if (state.DerivationData != Data)
		{
			throw TestException(std::string("Kat"), std::string("DUKPT"), std::string("Output does not match the known answer! -HK2"));
		}

		if (state.WorkingKey != Working)
		{
			throw TestException(std::string("Kat"), std::string("DUKPT"), std::string("Output does not match the known answer! -HK3"));
		}
	}

	void DUKPTTest::Initialize()
	{
		/*lint -save -e122 */
		/*lint -save -e146 */
		/*lint -save -e417 */

		const std::vector<std::string> bdk =
		{
			// aes-128
			std::string("FEDCBA9876543210F1F1F1F1F1F1F1F1"),
			// aes-256
			std::string("FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1")
		};
		HexConverter::Decode(bdk, 2, m_bdk);

		const std::vector<std::string> data =
		{
			// aes-128
			std::string("01011000000200809012345600000001"),
			std::string("01011000000200809012345600000002"),
			std::string("01011000000200809012345600000003"),
			std::string("010110000002008090123456FFFE4000"),
			std::string("010110000002008090123456FFFE8000"),
			std::string("010110000002008090123456FFFF0000"),
			// aes-256
			std::string("01021000000401009012345600000001"),
			std::string("01021000000401009012345600000002"),
			std::string("01021000000401009012345600000003"),
			std::string("010210000004010090123456FFFE4000"),
			std::string("010210000004010090123456FFFE8000"),
			std::string("010210000004010090123456FFFF0000")
		};
		HexConverter::Decode(data, 12, m_derivationdata);

		const std::vector<std::string> ikey =
		{
			// aes-128
			std::string("1273671EA26AC29AFA4D1084127652A1"),
			// aes-256
			std::string("CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F")
		};
		HexConverter::Decode(ikey, 2, m_initialkey);

		HexConverter::Decode("1234567890123456", m_initialkeyid);

		const std::vector<std::string> dkeys =
		{
			// aes-128
			std::string("4F21B565BAD9835E112B6465635EAE44"),
			std::string("2F34D68DE10F68D38091A73B9E7C437C"),
			std::string("031504E530365CF81264238540518318"),
			std::string("396C2C7CA1EA701C03B86B7D41F0C562"),
			std::string("0387625F189B58AE03EF0E8CCA41105E"),
			std::string("F6BA59389BD14A9855BE9727E7C52E3C"),
			// aes-256
			std::string("54AC2B32B145EA4A554CB8BC44B17467063A799856B1CCC2A138D36E8DBF78B3"),
			std::string("5DD5A0253842BBBE1D7C0DA27021412C6F1FAB53FB928DEAE56DA06090A9DE97"),
			std::string("8EEEF7C464AE415BB1D73FAED21993CD669F7999092A579EC6DD3CC680C65171"),
			std::string("FF20E1BB575539ACCB44E3111BE8757F83AE8549A2DD71B441A4A424F7FFD4B1"),
			std::string("630535C9C53E1EC6524016930B56F6728909C45403536B419AEBCB25B7351C07"),
			std::string("6D6DB7AAAE8B3EA90E57A39E4BBA71E173B21B446B30A78D64BFC6A8806C55EE")
		};
		HexConverter::Decode(dkeys, 12, m_derivationkey);

		const std::vector<std::string> working =
		{
			// aes-128
			std::string("AF8CB133A78F8DC2D1359F18527593FB"),
			std::string("D30BDC73EC9714B000BEC66BDB7B6D09"),
			std::string("7D69F01F3B45449F62C7816ECE723268"),
			std::string("6239A27F572DEDB17BCA1AC413EF9FE9"),
			std::string("F10C1404137A80718FCCE8BD90FF9F67"),
			std::string("27EFAC1D158632588F4AC69E45C247C4"),
			// aes-256
			std::string("8C1AB7BEE973829E30242E0BBBDD4946D540C98FC1B5BDCF94790001A23FD502"),
			std::string("3583D6CD02FC38822CC71A8D7678E04F4A8556335E6CC66863D3DADC5AEE2C62"),
			std::string("96A1AB5D37CB7CF81DDE64F66C46E0389B833E7AD5F4E44C791F04FAFDA6DA0E"),
			std::string("F388FF9FB1D66E8812BC67CA5B85CE5554063E09A2440EC1AF4EB433CCFBAF35"),
			std::string("FAC4E05A67AB1522505CF0E94E5977B99D0E5B116D76ABB6B8A64F0D785FF6DF"),
			std::string("88B82556AEF4A681E0687F443A4C4F305AF9203B114470DFC77C7F08BC43F9DA")
		};
		HexConverter::Decode(working, 12, m_workingKey);
		/*lint -restore */
	}
}
