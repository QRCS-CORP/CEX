#ifndef CEXTEST_SECURESTREAMTEST_H
#define CEXTEST_SECURESTREAMTEST_H

#include "ITest.h"
#include "../CEX/MemoryStream.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureStream.h"

namespace Test
{
	/// <summary>
	/// SecureStream test; compares reads and writes, and serialization
	/// </summary>
	class SecureStreamTest final : public ITest
	{
	private:

		static const std::string CLASSNAME;
		static const std::string DESCRIPTION;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;

	public:

		/// <summary>
		/// Initialize this class
		/// </summary>
		SecureStreamTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~SecureStreamTest();

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

		/// <summary>
		/// Test functions for correctness
		/// </summary>
		void Evaluate();

		/// <summary>
		/// Serialization tests
		/// </summary>
		void Serialization();

	private:

		void OnProgress(const std::string &Data);
	};
}

#endif
