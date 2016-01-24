#ifndef _CEXTEST_MACSTREAMTEST_H
#define _CEXTEST_MACSTREAMTEST_H

#include "ITest.h"
#include "CSPPrng.h"
#include "IMac.h"
#include "CMAC.h"
#include "HMAC.h"
#include "VMAC.h"
#include "SHA256.h"
#include "RHX.h"
#include "MacStream.h"
#include "MemoryStream.h"
#include "IByteStream.h"

namespace Test
{
	using namespace CEX::Mac;
	using CEX::Digest::SHA256;
	using CEX::Cipher::Symmetric::Block::RHX;
	using CEX::Prng::CSPPrng;

	/// <summary>
	/// Tests the MacStream class output against direct output from an HMAC instance
	/// </summary>
	class MacStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "MacStream output test; compares output from an SHA-2 512 HMAC and MacStream.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All MacStream tests have executed succesfully.";

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
		/// Compare MacStream output to Mac instance output
		/// </summary>
		MacStreamTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~MacStreamTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				std::vector<byte> key(64);
				std::vector<byte> iv(32);
				CSPPrng rnd;

				rnd.GetBytes(key);
				rnd.GetBytes(iv);

				SHA256* sha = new SHA256();
				HMAC* hmac = new HMAC(sha);
				hmac->Initialize(key, iv);
				CompareOutput(hmac);
				delete sha;
				delete hmac;
				OnProgress("Passed MacStream HMAC comparison tests..");

				key.resize(32);
				iv.resize(16);
				RHX* eng = new RHX();
				CMAC* cmac = new CMAC(eng, 128);
				cmac->Initialize(key, iv);
				CompareOutput(cmac);
				delete eng;
				delete cmac;
				OnProgress("Passed MacStream CMAC comparison tests..");

				iv.resize(32);
				rnd.GetBytes(iv);
				VMAC* vmac = new VMAC();
				vmac->Initialize(key, iv);
				CompareOutput(vmac);
				delete vmac;
				OnProgress("Passed MacStream VMAC comparison tests..");

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
		void CompareOutput(IMac* Engine)
		{
			using CEX::IO::IByteStream;
			using CEX::IO::MemoryStream;

			CSPPrng rnd;
			std::vector<byte> data(rnd.Next(1000, 10000));
			rnd.GetBytes(data);

			// mac instance for baseline
			unsigned int macSze = Engine->MacSize();
			std::vector<byte> code1(macSze);
			Engine->ComputeMac(data, code1);

			// test stream method
			std::vector<byte> code2(macSze);
			CEX::Processing::MacStream ds(Engine);
			IByteStream* ms = new MemoryStream(data);
			code2 = ds.ComputeMac(ms);

			if (code1 != code2)
				throw std::string("MacStreamTest: Expected hash is not equal!");

			// test byte access method
			code2 = ds.ComputeMac(data, 0, data.size());

			if (code1 != code2)
				throw std::string("MacStreamTest: Expected hash is not equal!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
