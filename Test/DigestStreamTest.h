#ifndef CEXTEST_DIGESTSTREAMTEST_H
#define CEXTEST_DIGESTSTREAMTEST_H

#include "ITest.h"
#include "../CEX/IDigest.h"

namespace Test
{
	/// <summary>
	/// Tests the DigestStream class output against direct output from a digest instance
	/// </summary>
	class DigestStreamTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

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
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Evaluate the digest steam for correct operation
		/// </summary>
		void Evaluate(Enumeration::Digests Engine);

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif
