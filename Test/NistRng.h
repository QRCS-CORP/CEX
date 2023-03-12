#ifndef CEXTEST_NISTRNG_H
#define CEXTEST_NISTRNG_H

#include "ITest.h"
#include "../CEX/ECB.h"
#include "../CEX/PrngBase.h"
#include "../CEX/Prngs.h"

namespace Test
{
	using Exception::CryptoRandomException;
	using Cipher::Block::Mode::ECB;
	using Enumeration::ErrorCodes;
	using Prng::PrngBase;
	using Test::ITest;
	using Enumeration::Prngs;

	class NistRng : public PrngBase
	{
	private:

		static std::string CLASSNAME;
		static const size_t RNG_MAX_RESEED = 100000;
		static const size_t RNG_SEED_SIZE = 48;
		class NistRngState;
		std::unique_ptr<NistRngState> m_nistRngState;
		std::unique_ptr<ECB> m_rngGenerator;

	public:

		NistRng();

		~NistRng();

		void Initialize(const std::vector<uint8_t> &Seed);

		void Initialize(const std::vector<uint8_t> &Seed, const std::vector<uint8_t> &Info);

		virtual const Prngs Enumeral() override;

		virtual const std::string Name() override;

		virtual void Generate(std::vector<uint8_t>& Output, size_t Offset, size_t Length) override;

		virtual void Generate(SecureVector<uint8_t>& Output, size_t Offset, size_t Length) override;

		virtual void Generate(std::vector<uint8_t>& Output) override;

		virtual void Generate(SecureVector<uint8_t>& Output) override;

		virtual uint16_t NextUInt16() override;

		virtual uint32_t NextUInt32() override;

		virtual uint64_t NextUInt64() override;

		virtual void Reset() override;

		void Update(const std::vector<uint8_t> &Seed, std::vector<uint8_t> &Key, std::vector<uint8_t> &IV);
	};
}

#endif
