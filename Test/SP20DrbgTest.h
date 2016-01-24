#ifndef _CEXTEST_SP20DRBGTEST_H
#define _CEXTEST_SP20DRBGTEST_H

#include "ITest.h"
#include "SP20Drbg.h"

namespace Test
{
	using CEX::Generator::SP20Drbg;

	/// <summary>
	/// Tests the SP20DRBG implementation using vector comparisons.
	/// <para>Uses vectors derived from the .NET CEX implementation.</para>
	/// </summary>
	class SP20DrbgTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "SP20DRBG implementations vector comparison tests.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All SP20DRBG tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<byte> _iv;
		std::vector<byte> _key;
		std::vector<byte> _output128;
		std::vector<byte> _output256;

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
		/// Compares known answer SP20DRBG Drbg vectors for equality
		/// </summary>
		SP20DrbgTest()
			:
			_key(16, 0),
			_iv(16, 0)
		{
			HexConverter::Decode("0323103b248efe859cd4ca57559a1c4aa4f9320635bac3807d93b7bcfbad14d1", _output128);
			HexConverter::Decode("d00b46e37495862e642c35be3a1149a8562ee50cdafe3a5f4b26a5c579a45c36", _output256);
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~SP20DrbgTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareVector(24, _output128);
				OnProgress("SP20Drbg: Passed 128bit vector comparison tests..");
				CompareVector(40, _output256);
				OnProgress("SP20Drbg: Passed 256bit vector comparison tests..");

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
		void CompareVector(int KeySize, std::vector<byte> Expected)
		{
			std::vector<byte> key(KeySize);
			std::vector<byte> output(1024);

			for (int i = 0; i < KeySize; i++)
				key[i] = (byte)i;

			SP20Drbg spd(20);
			spd.Initialize(key);
			spd.Generate(output);

			while (output.size() > 32)
				output = TestUtils::Reduce(output);

			if (output != Expected)
				throw std::string("SP20Drbg: Failed comparison test!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif
