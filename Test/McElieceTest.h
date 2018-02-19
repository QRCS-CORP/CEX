#ifndef CEXTEST_MCELIECETEST_H
#define CEXTEST_MCELIECETEST_H

#include "ITest.h"
#include "../CEX/BCR.h"

namespace Test
{
	/// <summary>
	/// McEliece key generation, encryption, and decryption tests
	/// </summary>
	class McElieceTest final : public ITest
	{
	private:

		static const std::string DESCRIPTION;
		static const std::string FAILURE;
		static const std::string SUCCESS;

		TestEventHandler m_progressEvent;
		Prng::BCR* m_rngPtr;

	public:

		/// <summary>
		/// Constructor
		/// </summary>
		McElieceTest();

		/// <summary>
		/// Destructor
		/// </summary>
		~McElieceTest();

		/// <summary>
		/// Start the tests
		/// </summary>
		std::string Run() override;

		/// <summary>
		/// Get: The test description
		/// </summary>
		const std::string Description() override;

		/// <summary>
		/// Progress return event callback
		/// </summary>
		TestEventHandler &Progress() override;

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
