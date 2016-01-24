#ifndef _CEXTEST_DIGESTSTREAMTEST_H
#define _CEXTEST_DIGESTSTREAMTEST_H

#include "ITest.h"
#include "CSPPrng.h"
#include "Digests.h"
#include "IDigest.h"
#include "DigestStream.h"
#include "DigestFromName.h"
#include "MemoryStream.h"
#include "IByteStream.h"

namespace Test
{
	using CEX::Enumeration::Digests;

	/// <summary>
	/// Tests the DigestStream class output against direct output from a digest instance
	/// </summary>
	class DigestStreamTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "DigestStream output test; compares output from SHA 256/512 digests and DigestStream.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All DigestStream tests have executed succesfully.";

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
		/// Compare DigestStream output to the digest output
		/// </summary>
		DigestStreamTest()
		{
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~DigestStreamTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareOutput(Digests::SHA256);
				OnProgress("Passed DigestStream SHA256 comparison tests..");

				CompareOutput(Digests::SHA512);
				OnProgress("Passed DigestStream SHA512 comparison tests..");

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
		void CompareOutput(CEX::Enumeration::Digests Engine)
		{
			using CEX::Prng::CSPPrng;
			using CEX::Digest::IDigest;
			using CEX::Helper::DigestFromName;
			using CEX::IO::IByteStream;
			using CEX::IO::MemoryStream;

			CSPPrng rnd;
			std::vector<byte> data(rnd.Next(1000, 10000));
			rnd.GetBytes(data);

			// digest instance for baseline
			IDigest* eng = DigestFromName::GetInstance(Engine);
			unsigned int dgtSze = eng->DigestSize();
			std::vector<byte> hash1(dgtSze);
			eng->ComputeHash(data, hash1);
			delete eng;

			// test stream method
			std::vector<byte> hash2(dgtSze);
			CEX::Processing::DigestStream ds(Engine);
			IByteStream* ms = new MemoryStream(data);
			hash2 = ds.ComputeHash(ms);

			if (hash1 != hash2)
				throw std::string("DigestStreamTest: Expected hash is not equal!");

			// test byte access method
			hash2 = ds.ComputeHash(data, 0, data.size());

			if (hash1 != hash2)
				throw std::string("DigestStreamTest: Expected hash is not equal!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
