#ifndef _CEXTEST_SKEINTEST_H
#define _CEXTEST_SkeinTest_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	using Digest::IDigest;

	/// <summary>
	/// Tests the Skein digest implementation using vector comparisons.
	/// <para>Tests the 256, 512, and 1024 bit versions of Skein against known test vectors from the skein 1.3 document, appendix C:
    /// <see href="http://www.skein-hash.info/sites/default/files/skein1.3.pdf"/></para>
	/// </summary>
	class SkeinTest : public ITest
	{
	private:
		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		std::vector<std::vector<byte>> m_expected256;
		std::vector<std::vector<byte>> m_expected512;
		std::vector<std::vector<byte>> m_expected1024;
		std::vector<std::vector<byte>> m_message256;
		std::vector<std::vector<byte>> m_message512;
		std::vector<std::vector<byte>> m_message1024;
		TestEventHandler m_progressEvent;

	public:
		/// <summary>
		/// Get: The test description
		/// </summary>
		virtual const std::string Description() { return DESCRIPTION; }

		/// <summary>
		/// Progress return event callback
		/// </summary>
		virtual TestEventHandler &Progress() { return m_progressEvent; }

		/// <summary>
		/// Known answer tests for the 256, 512, and 1024 bit versions of Skein
		/// </summary>
		SkeinTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SkeinTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		virtual std::string Run();

	private:
		void CompareParallel(IDigest* Dgt1, IDigest* Dgt2);
		void CompareVector(IDigest* Digest, std::vector<byte> &Input, std::vector<byte> &Expected);
		void Initialize();
		void OnProgress(std::string Data);
		void TreeParamsTest();
	};
}

#endif
