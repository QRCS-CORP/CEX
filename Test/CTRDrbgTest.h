#ifndef _CEXTEST_DRBGTEST_H
#define _CEXTEST_DRBGTEST_H

#include "ITest.h"
#include "CTRDrbg.h"
#include "RHX.h"

namespace Test
{
	using CEX::Generator::CTRDrbg;
	using CEX::Cipher::Symmetric::Block::RHX;

	/// <summary>
	/// DRBG implementations vector comparison tests.
	/// <para>Uses vectors derived from the .NET CEX implementation.</para>
	/// </summary>
	class CTRDrbgTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "CTRDRBG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All CTRDRBG tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<byte> _iv;
		std::vector<byte> _key;
		std::vector<byte> _output;

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
		/// Compares known answer CTR Drbg vectors for equality
		/// </summary>
		CTRDrbgTest()
			:
			_key(16, 0),
			_iv(16, 0)
		{
			HexConverter::Decode("b621dbd634714c11d9e72953d580474b37780e36b74edbd5c4b3a506e5a41018", _output);
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~CTRDrbgTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareVector(_output);
				OnProgress("CTRDrbg: Passed vector comparison tests..");

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
		void CompareVector(std::vector<byte> Expected)
		{
			RHX* eng = new RHX();
			CTRDrbg ctd(eng);
			int ksze = 48;
			std::vector<byte> key(ksze);
			std::vector<byte> output(1024);

			for (int i = 0; i < ksze; i++)
				key[i] = (byte)i;

			ctd.Initialize(key);
			ctd.Generate(output);
			delete eng;

			while (output.size() > 32)
				output = TestUtils::Reduce(output);

			if (output != Expected)
				throw std::string("CTRDrbg: Failed comparison test!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
