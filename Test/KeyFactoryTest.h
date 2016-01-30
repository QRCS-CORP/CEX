#ifndef _CEXTEST_KEYFACTORYTEST_H
#define _CEXTEST_KEYFACTORYTEST_H

#include "ITest.h"
#include "CipherDescription.h"
#include "CipherKey.h"
#include "CSPPrng.h"
#include "KeyFactory.h"
#include "KeyGenerator.h"
#include "KeyParams.h"
#include "MemoryStream.h"
#include "MessageHeader.h"

namespace Test
{
	using CEX::Prng::CSPPrng;
	using CEX::Common::KeyParams;
	using CEX::Common::KeyGenerator;
	using CEX::Common::CipherDescription;
	using CEX::IO::MemoryStream;
	using namespace CEX::Enumeration;

	/// <summary>
	/// Tests factory extraction and serialization methods on various structs and the KeyFactory class
	/// </summary>
	class KeyFactoryTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "KeyFactory test; tests factory extraction and serialization methods.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All KeyFactory tests have executed succesfully.";

		TestEventHandler _progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return _progressEvent; }

		/// <summary>
		/// Compare KeyFactory output to Mac instance output
		/// </summary>
		KeyFactoryTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~KeyFactoryTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareKeySerialization();
				OnProgress("Passed KeyParams serialization tests..");

				CompareKeyExtraction();
				OnProgress("Passed KeyFactory creation and extraction tests..");

				CompareCipherKey();
				OnProgress("Passed CipherKey serialization and access tests..");

				CompareMessageHeader();
				OnProgress("Passed MessageHeader serialization and access tests..");

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

	private:
		void CompareKeySerialization()
		{
			CSPPrng rnd;
			KeyGenerator kg;

			for (int i = 0; i < 10; ++i)
			{
				// out-bound funcs return pointer to obj
				KeyParams* kp = kg.GetKeyParams(rnd.Next(1, 1024), rnd.Next(1, 128), rnd.Next(1, 128));
				MemoryStream* m = KeyParams::Serialize(*kp);
				KeyParams* kp2 = KeyParams::DeSerialize(*m);

				if (!kp->Equals(*kp2))
					throw std::string("KeyFactoryTest: Key serialization test has failed!");

				delete kp;
				delete kp2;
				delete m;
			}
		}

		void CompareKeyExtraction()
		{
			KeyGenerator kg;
			KeyParams* kp = kg.GetKeyParams(192, 16, 64);

			CipherDescription ds(
				SymmetricEngines::RHX,
				192,
				IVSizes::V128,
				CipherModes::CTR,
				PaddingModes::PKCS7,
				BlockSizes::B128,
				RoundCounts::R22,
				Digests::Skein512,
				64,
				Digests::SHA512);

			// in/out use a pointer
			MemoryStream* m = new MemoryStream;
			CEX::Processing::Factory::KeyFactory kf(m);
			kf.Create(ds, *kp);
			// init new instance w/ populated stream
			m->Seek(0, CEX::IO::SeekOrigin::Begin);
			CEX::Processing::Factory::KeyFactory kf2(m);
			// extract key and desc from stream
			CEX::Processing::Structure::CipherKey ck;
			KeyParams kp2;
			kf2.Extract(ck, kp2);

			if (!ds.Equals(ck.Description()))
				throw std::string("KeyFactoryTest: Description extraction has failed!");
			if (!kp->Equals(kp2))
				throw std::string("KeyFactoryTest: Key extraction has failed!");

			MemoryStream* m2 = new MemoryStream;
			CEX::Processing::Factory::KeyFactory kf3(m2);
			// test other create func
			kf3.Create(*kp, SymmetricEngines::RHX, 192, IVSizes::V128, CipherModes::CTR, PaddingModes::PKCS7,
				BlockSizes::B128, RoundCounts::R22, Digests::Skein512, 64, Digests::SHA512);

			m2->Seek(0, CEX::IO::SeekOrigin::Begin);
			CEX::Processing::Factory::KeyFactory kf4(m2);
			kf4.Extract(ck, kp2);

			if (!ds.Equals(ck.Description()))
				throw std::string("KeyFactoryTest: Description extraction has failed!");
			if (!kp->Equals(kp2))
				throw std::string("KeyFactoryTest: Key extraction has failed!");
			
			delete m;
			delete m2;
			delete kp;
		}

		void CompareCipherKey()
		{
			CipherDescription ds(
				SymmetricEngines::RHX,
				192,
				IVSizes::V128,
				CipherModes::CTR,
				PaddingModes::PKCS7,
				BlockSizes::B128,
				RoundCounts::R22,
				Digests::Skein512,
				64,
				Digests::SHA512);

			CSPPrng rnd;
			std::vector<byte> id(16);
			std::vector<byte> ek(16);
			rnd.GetBytes(id);
			rnd.GetBytes(ek);

			// test serialization
			CEX::Processing::Structure::CipherKey ck(ds, id, ek);
			std::vector<byte> sk = ck.ToBytes();
			CEX::Processing::Structure::CipherKey ck2(sk);
			if (!ck.Equals(ck2))
				throw std::string("KeyFactoryTest: CipherKey serialization has failed!");

			CEX::IO::MemoryStream* mk = ck.ToStream();
			CEX::Processing::Structure::CipherKey ck3(*mk);
			if (!ck.Equals(ck3))
				throw std::string("KeyFactoryTest: CipherKey serialization has failed!");

			// test access funcs
			ck.SetCipherDescription(*mk, ds);
			CipherDescription* ds2 = ck.GetCipherDescription(*mk);
			if (!ck.Description().Equals(*ds2))
				throw std::string("KeyFactoryTest: CipherKey access has failed!");
			delete ds2;

			rnd.GetBytes(ek);
			ck.SetExtensionKey(*mk, ek);
			if (ck.GetExtensionKey(*mk) != ek)
				throw std::string("KeyFactoryTest: CipherKey access has failed!");

			rnd.GetBytes(id);
			ck.SetKeyId(*mk, id);
			if (ck.GetKeyId(*mk) != id)
				throw std::string("KeyFactoryTest: CipherKey access has failed!");

			delete mk;
		}

		void CompareMessageHeader()
		{
			CSPPrng rnd;
			std::vector<byte> id(16);
			std::vector<byte> ex(16);
			std::vector<byte> ha(64);
			rnd.GetBytes(id);
			rnd.GetBytes(ex);
			rnd.GetBytes(ha);

			// test serialization
			CEX::Processing::Structure::MessageHeader mh(id, ex, ha);
			std::vector<byte> sk = mh.ToBytes();
			CEX::Processing::Structure::MessageHeader mh2(sk);
			if (!mh.Equals(mh2))
				throw std::string("KeyFactoryTest: MessageHeader serialization has failed!");

			CEX::IO::MemoryStream* mk = mh.ToStream();
			CEX::Processing::Structure::MessageHeader mh3(*mk, 64);
			if (!mh.Equals(mh3))
				throw std::string("KeyFactoryTest: MessageHeader serialization has failed!");

			std::vector<byte> ha2 = mh.GetMessageMac(*mk, 64);
			if (ha != ha2)
				throw std::string("KeyFactoryTest: MessageHeader access has failed!");

			std::vector<byte> id2 = mh.GetKeyId(*mk);
			if (id != id2)
				throw std::string("KeyFactoryTest: MessageHeader access has failed!");

			std::vector<byte> ex2 = mh.GetExtensionKey(*mk);
			if (ex != ex2)
				throw std::string("KeyFactoryTest: MessageHeader access has failed!");

			std::string ext1 = "test";
			std::vector<byte> enc = mh.EncryptExtension(ext1, mh.GetExtensionKey(*mk));
			std::string ext2 = mh.DecryptExtension(enc, mh.GetExtensionKey(*mk));
			if (ext1.compare(ext2) != 0)
				throw std::string("KeyFactoryTest: MessageHeader access has failed!");

			delete mk;
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
