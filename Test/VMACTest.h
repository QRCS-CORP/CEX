#ifndef _CEXTEST_VMACTEST_H
#define _CEXTEST_VMACTEST_H

#include "ITest.h"
#include "VMAC.h"

namespace Test
{
	using CEX::Mac::VMAC;

	/// <summary>
	/// VMAC implementation vector comparison tests.
	/// <para>Vector test used by the official documentation:
	/// <see href="http://vmpcfunction.com/vmpc_mac.pdf"/></para>
	/// </summary>
	class VMACTest : public ITest
	{
	private:
		const std::string DESCRIPTION = "VMAC Known Answer Test Vectors.";
		const std::string FAILURE = "FAILURE! ";
		const std::string SUCCESS = "SUCCESS! All VMAC tests have executed succesfully.";

		TestEventHandler _progressEvent;
		std::vector<byte> _expected;
		std::vector<byte> _input;
		std::vector<byte> _iv;
		std::vector<byte> _key;

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
		/// Compares known answer VMAC vectors for equality
		/// </summary>
		VMACTest()
			:
			_input(256)
		{
			HexConverter::Decode("9BDA16E2AD0E284774A3ACBC8835A8326C11FAAD", _expected);
			HexConverter::Decode("4B5C2F003E67F39557A8D26F3DA2B155", _iv);
			HexConverter::Decode("9661410AB797D8A9EB767C21172DF6C7", _key);

			for (unsigned int i = 0; i < _input.size(); i++)
				_input[i] = (byte)i;
		}

		/// <summary>
		/// Destructor
		/// </summary>
		~VMACTest()
		{
		}

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run()
		{
			try
			{
				CompareVector(_key, _iv, _expected);
				OnProgress("Passed VMAC vector tests..");
				CompareAccess(_key, _iv);
				OnProgress("Passed DoFinal/ComputeHash methods output comparison..");

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
		void CompareAccess(std::vector<byte> &Key, std::vector<byte> &Iv)
		{
			std::vector<byte> hash1(20);
			VMAC mac;

			mac.Initialize(Key, Iv);
			mac.BlockUpdate(_input, 0, _input.size());
			mac.DoFinal(hash1, 0);

			std::vector<byte> hash2(20);
			mac.ComputeMac(_input, hash2);

			if (hash1 != hash2)
				throw std::string("VMACTest: hash is not equal!");
		}

		void CompareVector(std::vector<byte> &Key, std::vector<byte> &Iv, std::vector<byte> &Expected)
		{
			std::vector<byte> hash(20);
			VMAC mac;

			mac.Initialize(Key, Iv);
			mac.BlockUpdate(_input, 0, _input.size());
			mac.DoFinal(hash, 0);

			if (Expected != hash)
				throw std::string("VMACTest: hash is not equal!");
		}

		void OnProgress(char* Data)
		{
			_progressEvent(Data);
		}
	};
}

#endif