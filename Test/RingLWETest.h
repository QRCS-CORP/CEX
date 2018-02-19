#ifndef CEXTEST_RINGLWETEST_H
#define CEXTEST_RINGLWETEST_H

#include "ITest.h"
#include "../CEX/BCR.h"

namespace Test
{
	/// <summary>
	/// RingLWE key generation, encryption, and decryption tests
	/// </summary>
	class RingLWETest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;
		Prng::BCR* m_rngPtr;

	public:

		/// <summary>
		///  Constructor
		/// </summary>
		RingLWETest();

		/// <summary>
		/// Destructor
		/// </summary>
		~RingLWETest();

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

	private:

		void CipherTextIntegrity();
		void MessageAuthentication();
		void PublicKeyIntegrity();
		void OnProgress(std::string Data);
		void StressLoop();
		void SerializationCompare();
	};
}

#endif
