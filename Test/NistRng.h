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

		static const std::string NistRng::CLASSNAME;
		static const size_t RNG_MAX_RESEED = 1000;
		static const size_t RNG_SEED_SIZE = 48;
		class NistRngState;
		std::unique_ptr<NistRngState> m_nistRngState;
		std::unique_ptr<ECB> m_rngGenerator;

	public:

		NistRng();

		~NistRng();

		void Initialize(const std::vector<byte> &Seed);

		void Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Info);

		virtual const Prngs Enumeral() override;

		virtual const std::string Name() override;

		virtual void Generate(std::vector<byte>& Output, size_t Offset, size_t Length) override;

		virtual void Generate(SecureVector<byte>& Output, size_t Offset, size_t Length) override;

		virtual void Generate(std::vector<byte>& Output) override;

		virtual void Generate(SecureVector<byte>& Output) override;

		virtual ushort NextUInt16() override;

		virtual uint NextUInt32() override;

		virtual ulong NextUInt64() override;

		virtual void Reset() override;

		void Update(const std::vector<byte> &Seed, std::vector<byte> &Key, std::vector<byte> &IV);
	};
}

#endif
