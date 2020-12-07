#include "CSXTest.h"
#include "../CEX/ChaCha.h"
#include "../CEX/CSX512.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SymmetricKey.h"

#if defined(__AVX2__)
#	include "../CEX/ULong256.h"
#endif
#if defined(__AVX512__)
#	include "../CEX/ULong512.h"
#endif

namespace Test
{
	using Cipher::Stream::ChaCha;
	using Cipher::Stream::CSX512;
	using Exception::CryptoAuthenticationFailure;
	using Exception::CryptoSymmetricException;
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Prng::SecureRandom;
	using Enumeration::StreamAuthenticators;
	using Cipher::SymmetricKey;
	using Cipher::SymmetricKeySize;

#if defined(__AVX2__)
	using Numeric::ULong256;
#endif

#if defined(__AVX512__)
	using Numeric::ULong512;
#endif

	const std::string CSXTest::CLASSNAME = "CSXTest";
	const std::string CSXTest::DESCRIPTION = "Tests the CSX stream cipher authenticated stream cipher.";
	const std::string CSXTest::SUCCESS = "SUCCESS! All CSX tests have executed succesfully.";

	//~~~Constructor~~~//

	CSXTest::CSXTest()
		:
		m_expected(0),
		m_key(0),
		m_message(0),
		m_monte(0),
		m_nonce(0),
		m_progressEvent()
	{
		Initialize();
	}

	CSXTest::~CSXTest()
	{
		IntegerTools::Clear(m_expected);
		IntegerTools::Clear(m_key);
		IntegerTools::Clear(m_message);
		IntegerTools::Clear(m_monte);
		IntegerTools::Clear(m_nonce);
	}

	//~~~Accessors~~~//

	const std::string CSXTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &CSXTest::Progress()
	{
		return m_progressEvent;
	}

	//~~~Public Functions~~~//

	std::string CSXTest::Run()
	{
		try
		{
			// CSXP80 is the default if CEX_CSX512_STRONG is defined in CexConfig, or CSXP40 as alternate
			CSX512* csx512a = new CSX512(true);
			CSX512* csx512s = new CSX512(false);

			Authentication(csx512a);
			OnProgress(std::string("CSXTest: Passed CSX-512 MAC authentication tests.."));

			CompareP1024();
			OnProgress(std::string("CSXTest: Passed CSX-512 permutation variants equivalence test.."));

			Exception(csx512s);
			OnProgress(std::string("CSXTest: Passed CSX-512 exception handling tests.."));

			Kat(csx512a, m_message[0], m_key[0], m_nonce[0], m_expected[0]);
			Kat(csx512a, m_message[0], m_key[1], m_nonce[0], m_expected[1]);
			Kat(csx512s, m_message[0], m_key[0], m_nonce[0], m_expected[2]);
			Kat(csx512s, m_message[0], m_key[1], m_nonce[0], m_expected[3]);
			OnProgress(std::string("CSXTest: Passed CSX-512 known answer cipher tests.."));

			Sequential(csx512a, m_message[0], m_key[0], m_nonce[0], m_expected[4], m_expected[5], m_expected[6]);
			OnProgress(std::string("CSXTest: Passed CSX-512 sequential transformation and authentication calls test.."));

			// tests the cipher state serialization feature
			Serialization();
			OnProgress(std::string("CSXTest: Passed CSX-512 state serialization test.."));

			MonteCarlo(csx512s, m_message[0], m_key[1], m_nonce[0], m_monte[0]);
			OnProgress(std::string("CSXTest: Passed CSX-512 monte carlo tests.."));

			Parallel(csx512s);
			OnProgress(std::string("CSXTest: Passed CSX-512 parallel to sequential equivalence test.."));

			Stress(csx512s);
			OnProgress(std::string("CSXTest: Passed CSX-512 stress tests.."));

			delete csx512a;
			delete csx512s;

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

	void CSXTest::Authentication(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t TAGLEN = Cipher->TagSize();
		const size_t MINSMP = 64;
		const size_t MAXSMP = 6400;
		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.IVSize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		cpt.reserve(MAXSMP + TAGLEN);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		// test large random-sized arrays
		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt.resize(MSGLEN + TAGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			rnd.Generate(inp, 0, MSGLEN);
			rnd.Generate(key, 0, key.size());
			rnd.Generate(nonce, 0, nonce.size());

			SymmetricKey kp(key, nonce);

			// encrypt plain-text
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);

			// decrypt cipher-text
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			// use constant time IntegerTools::Compare to verify mac
			if (IntegerTools::Compare(Cipher->Tag(), 0, cpt, MSGLEN, TAGLEN) == false)
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -CA1"));
			}

			if (IntegerTools::Compare(inp, 0, otp, 0, MSGLEN) == false)
			{
				throw TestException(std::string("Authentication"), Cipher->Name(), std::string("MAC output is not equal! -CA2"));
			}
		}
	}

	void CSXTest::CompareP1024()
	{
#if defined(CEX_CSX512_STRONG)
		const size_t ROUNDS = 80;
#else
		const size_t ROUNDS = 40;
#endif
		std::array<ulong, 2> counter{ 128, 1 };
		std::vector<byte> output1(128);
		std::array<ulong, 14> state;

		MemoryTools::Clear(state, 0, state.size() * sizeof(ulong));

		ChaCha::PermuteP1024C(output1, 0, counter, state, ROUNDS);

#if defined(__AVX512__)

		std::array<ulong, 16> counter16{ 128, 128, 128, 128, 128, 128, 128, 128, 1, 1, 1, 1, 1, 1, 1, 1 };
		std::vector<byte> output4(1024);

		ChaCha::PermuteP8x1024H(output4, 0, counter16, state, ROUNDS);

		for (size_t i = 0; i < 1024; i += 128)
		{
			for (size_t j = 0; j < 128; ++j)
			{
				if (output4[i + j] != output1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PermuteP16x512H"), std::string("Permutation output is not equal! -CP3"));
				}
			}
		}

#elif defined(__AVX2__)

		std::array<ulong, 8> counter8{ 128, 128, 128, 128, 1, 1, 1, 1 };
		std::vector<byte> output3(512);

		ChaCha::PermuteP4x1024H(output3, 0, counter8, state, ROUNDS);

		for (size_t i = 0; i < 512; i += 128)
		{
			for (size_t j = 0; j < 128; ++j)
			{
				if (output3[i + j] != output1[j])
				{
					throw TestException(std::string("CompareP512"), std::string("PermuteP8x512H"), std::string("Permutation output is not equal! -CP2"));
				}
			}
		}

#endif
	}

	void CSXTest::Exception(IStreamCipher* Cipher)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		// test initialization key input sizes
		try
		{
			std::vector<byte> key(ks.KeySize() + 1);
			SymmetricKey kp(key);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE1"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(1);
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE2"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}

		// test invalid parallel options
		try
		{
			std::vector<byte> key(ks.KeySize());
			std::vector<byte> nonce(ks.IVSize());
			SymmetricKey kp(key, nonce);

			Cipher->Initialize(true, kp);
			Cipher->ParallelMaxDegree(9999);

			throw TestException(std::string("Exception"), Cipher->Name(), std::string("Exception handling failure! -CE6"));
		}
		catch (CryptoSymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}
	}

	void CSXTest::Kat(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		const size_t CPTLEN = Cipher->IsAuthenticator() ? Message.size() + Cipher->TagSize() : Message.size();
		const size_t MSGLEN = Message.size();
		std::vector<byte> aad(20, 0x01);
		std::vector<byte> cpt(CPTLEN);
		std::vector<byte> otp(MSGLEN);
		SymmetricKey kp(Key, Nonce);

		// encrypt
		Cipher->Initialize(true, kp);

		if (Cipher->IsAuthenticator())
		{
			Cipher->SetAssociatedData(aad, 0, aad.size());
		}

		Cipher->Transform(Message, 0, cpt, 0, MSGLEN);

		if (IntegerTools::Compare(cpt, 0, Expected, 0, Expected.size()) == false)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Output does not match the known answer! -CK2"));
		}

		// decrypt
		Cipher->Initialize(false, kp);

		if (Cipher->IsAuthenticator())
		{
			Cipher->SetAssociatedData(aad, 0, aad.size());
		}

		Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

		if (otp != Message)
		{
			throw TestException(std::string("Kat"), Cipher->Name(), std::string("Decrypted output does not match the input! -CK1"));
		}
	}

	void CSXTest::MonteCarlo(IStreamCipher* Cipher, std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce, std::vector<byte> &Expected)
	{
		const size_t MSGLEN = Message.size();
		std::vector<byte> msg = Message;
		std::vector<byte> enc(MSGLEN);
		std::vector<byte> dec(MSGLEN);
		Cipher::SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(msg, 0, enc, 0, msg.size());
			msg = enc;
		}

		if (enc != Expected)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Encrypted output does not match the expected! -CM1"));
		}

		Cipher->Initialize(false, kp);

		for (size_t i = 0; i != MONTE_CYCLES; i++)
		{
			Cipher->Transform(enc, 0, dec, 0, enc.size());
			enc = dec;
		}

		if (dec != Message)
		{
			throw TestException(std::string("MonteCarlo"), Cipher->Name(), std::string("Decrypted output does not match the input! -CM2"));
		}
	}

	void CSXTest::Parallel(IStreamCipher* Cipher)
	{
		const uint MINSMP = static_cast<uint>(Cipher->ParallelBlockSize());
		const uint MAXSMP = static_cast<uint>(Cipher->ParallelBlockSize()) * 4;
		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];
		std::vector<byte> cpt1;
		std::vector<byte> cpt2;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.IVSize());
		std::vector<byte> otp;
		Prng::SecureRandom rnd;

		cpt1.reserve(MAXSMP);
		cpt2.reserve(MAXSMP);
		inp.reserve(MAXSMP);
		otp.reserve(MAXSMP);

		for (size_t i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXSMP, MINSMP));
			cpt1.resize(MSGLEN);
			cpt2.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
			SymmetricKey kp(key, nonce);

			// sequential
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = false;
			Cipher->Transform(inp, 0, cpt1, 0, MSGLEN);

			// parallel
			Cipher->Initialize(true, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(inp, 0, cpt2, 0, MSGLEN);

			if (cpt1 != cpt2) //17280-16488
			{
				for (size_t j = 0; j < cpt1.size(); ++j)
				{
					if (cpt1[j] != cpt2[j])
					{
						throw;
					}
				}
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -CP1"));
			}

			// decrypt sequential ciphertext with parallel
			Cipher->Initialize(false, kp);
			Cipher->ParallelProfile().IsParallel() = true;
			Cipher->Transform(cpt1, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Parallel"), Cipher->Name(), std::string("Cipher output is not equal! -CP2"));
			}
		}
	}

	void CSXTest::Sequential(IStreamCipher* Cipher, const std::vector<byte> &Message, std::vector<byte> &Key, std::vector<byte> &Nonce,
		const std::vector<byte> &Output1, const std::vector<byte> &Output2, const std::vector<byte> &Output3)
	{
		std::vector<byte> aad(20, 0x01);
		std::vector<byte> dec1(Message.size());
		std::vector<byte> dec2(Message.size());
		std::vector<byte> dec3(Message.size());
		std::vector<byte> otp1(Output1.size());
		std::vector<byte> otp2(Output2.size());
		std::vector<byte> otp3(Output3.size());

		SymmetricKey kp(Key, Nonce);

		Cipher->Initialize(true, kp);
		Cipher->SetAssociatedData(aad, 0, aad.size());
		Cipher->Transform(Message, 0, otp1, 0, Message.size());

		if (otp1 != Output1)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS1"));
		}

		Cipher->Transform(Message, 0, otp2, 0, Message.size());

		if (otp2 != Output2)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS2"));
		}

		Cipher->Transform(Message, 0, otp3, 0, Message.size());

		if (otp3 != Output3)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Encrypted output is not equal! -AS3"));
		}

		// test inverse operation -decryption mode
		Cipher->Initialize(false, kp);
		Cipher->SetAssociatedData(aad, 0, aad.size());

		try
		{
			Cipher->Transform(otp1, 0, dec1, 0, dec1.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS4"));
		}

		if (dec1 != Message)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS5"));
		}

		try
		{
			Cipher->Transform(otp2, 0, dec2, 0, dec2.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS6"));
		}

		if (dec2 != Message)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS7"));
		}

		try
		{
			Cipher->Transform(otp3, 0, dec3, 0, dec3.size());
		}
		catch (CryptoAuthenticationFailure const&)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Authentication failure! -AS8"));
		}

		if (dec3 != Message)
		{
			throw TestException(std::string("Sequential"), Cipher->Name(), std::string("AeadTest: Decrypted output is not equal! -AS9"));
		}
	}

	void CSXTest::Serialization()
	{
		const size_t TAGLEN = 64;
		const size_t MSGLEN = 137;
		CSX512 cpr1(true);
		Cipher::SymmetricKeySize ks = cpr1.LegalKeySizes()[0];
		std::vector<byte> cpt1(MSGLEN + TAGLEN);
		std::vector<byte> cpt2(MSGLEN + TAGLEN);
		std::vector<byte> key(ks.KeySize(), 0x01);
		std::vector<byte> cust(ks.InfoSize(), 0x02);
		std::vector<byte> msg(MSGLEN, 0x03);
		std::vector<byte> nonce(ks.IVSize(), 0x04);
		std::vector<byte> plt1(MSGLEN);
		std::vector<byte> plt2(MSGLEN);

		SymmetricKey kp(key, nonce, cust);
		cpr1.Initialize(true, kp);

		SecureVector<byte> sta1 = cpr1.Serialize();
		CSX512 cpr2(sta1);

		cpr1.Transform(msg, 0, cpt1, 0, msg.size());
		cpr2.Transform(msg, 0, cpt2, 0, msg.size());

		if (cpt1 != cpt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS1"));
		}

		cpr1.Initialize(false, kp);

		SecureVector<byte> sta2 = cpr1.Serialize();
		CSX512 cpr3(sta2);

		cpr1.Transform(cpt1, 0, plt1, 0, plt1.size());
		cpr3.Transform(cpt2, 0, plt2, 0, plt2.size());

		if (plt1 != msg || plt1 != plt2)
		{
			throw TestException(std::string("Serialization"), cpr1.Name(), std::string("Transformation output is not equal! -SS2"));
		}
	}

	void CSXTest::Stress(IStreamCipher* Cipher)
	{
		const uint MINPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize());
		const uint MAXPRL = static_cast<uint>(Cipher->ParallelProfile().ParallelBlockSize() * 4);

		Cipher::SymmetricKeySize ks = Cipher->LegalKeySizes()[0];

		std::vector<byte> cpt;
		std::vector<byte> inp;
		std::vector<byte> key(ks.KeySize());
		std::vector<byte> nonce(ks.IVSize());
		std::vector<byte> otp;
		SecureRandom rnd;
		size_t i;

		cpt.reserve(MAXM_ALLOC);
		inp.reserve(MAXM_ALLOC);
		otp.reserve(MAXM_ALLOC);

		for (i = 0; i < TEST_CYCLES; ++i)
		{
			const size_t MSGLEN = static_cast<size_t>(rnd.NextUInt32(MAXPRL, MINPRL));
			cpt.resize(MSGLEN);
			inp.resize(MSGLEN);
			otp.resize(MSGLEN);

			rnd.Generate(key, 0, key.size());
			rnd.Generate(inp, 0, MSGLEN);
			SymmetricKey kp(key, nonce);

			// encrypt
			Cipher->Initialize(true, kp);
			Cipher->Transform(inp, 0, cpt, 0, MSGLEN);
			// decrypt
			Cipher->Initialize(false, kp);
			Cipher->Transform(cpt, 0, otp, 0, MSGLEN);

			if (otp != inp)
			{
				throw TestException(std::string("Stress"), Cipher->Name(), std::string("Transformation output is not equal! -CS1"));
			}
		}
	}

	//~~~Private Functions~~~//

	void CSXTest::Initialize()
	{
		const std::vector<std::string> expected =
		{
#if defined(CEX_CSX512_STRONG)
			std::string("1F1CAC80419D554861FB90D8A9FFC4BBE1C833754A95CE84C280E96AD0652FBD054D82477162DA45CCF64F8935E9EAAA73314FC277DBECFFBF50688E64C1F3EA"
				"279196ADE5F84A132B7764DAED71CD783475A4335776E8D39B012455211AFFF2B99130AB8AF358ECFA906D4E4151FEC2F96145163EBE200577DC99C1953EFF41"
				"29A875B6CF26191E2EC513FD150D7526BDB7FDAB48DD4DF0F4E6AF4F9359A72159A71AF3BB15AE1300B0AA5843A7B1534D1D493D8C56CAE6E7B3CD7449787202"),
			std::string("2D5B6911F9035C5117467AC5F7A763621E80F79446B99DA8DDFFBE994AD992846E00DF99968C97C54F7EDEAD0D4C6BDA895788408A4B8D92AF9A56709672B574"
				"0541BCA6B8D942CF8D60573C43F68830F17D86EA0DCF64BFC24D35D95F597A73AE798C7B53BCD71D3DFE08677B808FBE9D651A6EF7F98D8E17CD0116CF1300CC"
				"350300392216DBCE9FD267EC152FA5957CFF2CC0F34B86AB749B131776D99524EC45ECBF1EEB73EF7B1864CFC8B0CB1DB43F2B64E9766458DDB7FBA9C73F61DB"),
			std::string("62A7F1D795194B20B78C2D10988ED083BBCE1B4DFD4EDF9D62F505D20705E3478F72B56E3317F12D76919FA6E4977008871A0A8A052D5D430C7371EC98985CEA"
				"AC680E8A7DC51E3D70D2A74E951842681E7E844E518D093CD75355B643895B0AB0DAC049502DD6940815B1A110ED200F642608B7FCA15484290E748F48C622D9"),
			std::string("093AD45F3ACEBA5ACA1937B4D04B48D5B19E2ACCF5B54FF518F3243A96F01C1B5F83611252392175F9218217886FE4AACFC528B304AEB34FFFAD4A69240605A7"
				"79D62B825662594CFF42F57E4F576152D24A91069CD3BD4201226F344D3FB6CE841EA3F1AD3E1511915C2E2B4B6FC17AA19B06F0A4B145AAF76738794BFCE38B"),

			std::string("1F1CAC80419D554861FB90D8A9FFC4BBE1C833754A95CE84C280E96AD0652FBD054D82477162DA45CCF64F8935E9EAAA73314FC277DBECFFBF50688E64C1F3EA"
				"279196ADE5F84A132B7764DAED71CD783475A4335776E8D39B012455211AFFF2B99130AB8AF358ECFA906D4E4151FEC2F96145163EBE200577DC99C1953EFF41"
				"29A875B6CF26191E2EC513FD150D7526BDB7FDAB48DD4DF0F4E6AF4F9359A72159A71AF3BB15AE1300B0AA5843A7B1534D1D493D8C56CAE6E7B3CD7449787202"),
			std::string("2DDB95977A275614037B532B76D55BDD4DB8E10F4E56064A392FA6A7BAAC84F27A3A7BC04E7DF8DD3BF50B763EEE9B9BD14D91131445313F0D2A22C0416A58D2"
				"DBA889EE9B28AF4ECE9D2FC3D2C445A7093D77C8818D7CF1552C1F7798DE962DE39C26FD012046A09AE3C2ECEA62311ECE7AA25D4CAD74DA7741230394010650"
				"DA83530EEA08C1AAE51B445C22164353CF364B0947794A4BC71C604A343322BD7884CD3210AC1AEC0317983612FC98A82576042983416183A347C0079E21478C"),
			std::string("733CCBB6827A53CE81E1A4C9C681D170EEDBD76119F0EFF750C4113EFC2A998E1C1181C4E4B9050F3DCAF621932E9E8AC110263CCBB4871A54D30AAD9C722B4F"
				"B5B28473D58CEAD9487FDCD8A19724A0F004C64C51CC65239432E5403449AC194343FB358C83520D8D7A457807A0F905942A18A284686AAE51508A4CC806C959"
				"2CDE2FC9F246785411E61B8AC41712D3D8BB009EDA47A51538B251145F53A0A56965B1BEAD6945AD31297E7F52938708B22C8B7CD3E27FD2EFC204E97C7116AB"),
#else
			std::string("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
				"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
				"2EC8B5F4E79AD2F7A86140499FB479E9BD0EEB065E91E4F7F53953E970AA13DC96172F398E598FF7169C41A8D8E51FAF297004B2B1F242706EE34680CF9A9F9A"),
			std::string("D1A7965A4B322260EB7BC8206F8EC96B9912F9E3A797D41364F03BEF9FCA8772AF7168C9A1FFAB6269E1E3B51FAA6B6B8D6A2ECAE3C61825E0FD3BA13775F030"
				"FC74B6D1A2439F6B7E2962D62FABD28AF7D202FC0533EDD4780D935F38966367CA71BCBA74967745210BE969CB829B63C48DC5CC89ED9C4EE1F9D614A3A488B9"
				"F23113EA8E74BA2D4735BD96ED1414E22FBFFCDC64186605CA2F8E81727B16946334570EF3A6F73B37B6E35EE1EE77CA69838BDCB26126E91ADDD9A8F998FF40"),
			std::string("E1E27CD3CF085080363AC3903D31C2AE5E51D4CCF8FB9278FEFB24077A72C2AC671249C32DED5F96CBC31702CED6B3575F3B562BA9FF9E6467DE7C687AEDA54C"
				"7043FC912BF57B4892FED02E5F4D67C2404DCF99B6021FDBD1B241DBD8673F96D67A15AC380946EBE5287C61F74C8ECD6A34AF7499D145F1B74BED2A5A7CA631"),
			std::string("73074BECE0637023B8B3F6F658C3873159DEA01F65DDE3F3BD4DB4B86F151E4D517891E2290998F0EE8C4FE4B4DF6A9868F378C6BF37ED2CDAF6BB239F0BBA9C"
				"A3EE2C7AEEF58438A5E2E1195AA344E16F0075EA5DE53F342E8FA8AB844BDD193204624693D79A3F8A3BF19AB3D9D1141FF9AF1A5DF8D79C96A9D1968F4B1906"),

			std::string("F726CF4BECEBDFDE9275C54B5284D0CDEEF158D8E146C027B731B6EF852C008F842B15CD0DCF168F93C9DE6B41DEE964D62777AA999E44C6CFD903E65E0096EF"
				"A271F75C45FE13CE879973C85934D0B43B49BC0ED71AD1E72A9425D2FCDA45FD1A56CE66B25EA602D9F99BDE6909F7D73C68B8A52870577D30F0C0E4D02DE2E5"
				"2EC8B5F4E79AD2F7A86140499FB479E9BD0EEB065E91E4F7F53953E970AA13DC96172F398E598FF7169C41A8D8E51FAF297004B2B1F242706EE34680CF9A9F9A"),
			std::string("379E86BCE2F0BE6DF0BAA8FEC403C6A7244B21D1D5B9193FCE79510FF2633893F58D57DABBEF0424E1E8D5ED7B485EB7381CC7235350220CA03F1D107A102BD3"
				"5FAB74869AB656D35E0F40950E1564DBDC37ECFD6C50BEE201BFA0F953AEC0A29B063993F5D019CDDE4A8AA02D440C19A4A08AD7A0CD3F2FDFEF61D0383314B5"
				"1C3D8B4D0B66FBD4BC70E6472809857194D2646A8F3764C5AE5649546F6154910D0C8F2802B7CE6ACBB4BFFC79FE6E2D4F2D2DC501AC847B985FECC670A67BF7"),
			std::string("7F804A9C7DEE675B1C6DA673965DDDB3DD52F94D603C6223864871DD705AE8C7222501387319D2817DF647E840972BFE242079ECA4B12E28835BBFDBE4AA9ABF"
				"B462F0B7BE2D5A863140DEA758EA8EB49C60C1CEEF64A7B5F25F588D0ED4777E2305957F7C695EB20AD23A20035461C6C7EDBB35F4B0B1979D156387A5214A4E"
				"1D07B80191608A7FB97FA2C16C969A0717D6481F88500D235445F595D4484F3ACEC8A6C5AFA80DB8B4A338402786B3BA5D2E36B2E0CB0A394D77A470D7C3CC30")
#endif

		};
		HexConverter::Decode(expected, 7, m_expected);

		const std::vector<std::string> key =
		{
			std::string("0053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF12"),
			std::string("0558ABFE51A4F74A9DF04396E93C8FE23588DB2E81D4277ACD2073C6196CBF120053A6F94C9FF24598EB3E91E4378ADD3083D6297CCF2275C81B6EC11467BA0D")
		};
		HexConverter::Decode(key, 2, m_key);

		const std::vector<std::string> message =
		{
			std::string("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
				"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
		};
		HexConverter::Decode(message, 1, m_message);

		const std::vector<std::string> monte =
		{
#if defined(CEX_CSX512_STRONG)
			std::string("913A8DE79CEDA1B4BCAAD061CAE3F529BC3CA231FA10E2755FD4BD3EDCBA8CE64BB84C4A8630CF497906BC0571CF36D1614DE64F13F82F08165C0B5ECD2A907C"
				"07F172B88D200158E588CFEA410D676299C2441221FA0EC74AF57CF9A2B87359AFF384B213E63605601B41C6E18F3BFFF5ACCCDB618D7A86F0CCE53CD18F5846")
#else
			std::string("851E39276409FA9E7707F049898AD0E684CA54A03FFD7BC24C5ECD6937B356D5DFFCAE6B71C14AA07E2C592CBDF75B19F1917184B901F54CBBE8DAD676717DA5"
				"799F28C4EB24B42DF760C82A477F1A37DB9523A852B964A5913AA668C3ED564FE80980CABDFD1E91C4A1153B45ADA85A6886B3C2F1D6EC8C7AAA7793FF088BDB")
#endif
		};
		HexConverter::Decode(monte, 1, m_monte);

		const std::vector<std::string> nonce =
		{
			std::string("000102030405060708090A0B0C0D0E0F")
		};
		HexConverter::Decode(nonce, 1, m_nonce);

		/*lint -restore */
	}

	void CSXTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}