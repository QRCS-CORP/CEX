#include "NistRng.h"
#include "../CEX/CSP.h"
#include "../CEX/IntegerTools.h"
#include "../CEX/MemoryTools.h"

namespace Test
{
	using Tools::IntegerTools;
	using Tools::MemoryTools;
	using Cipher::SymmetricKey;

	std::string NistRng::CLASSNAME = "NistRng";

	class NistRng::NistRngState
	{
	public:

		std::vector<uint8_t> Key;
		std::vector<uint8_t> Nonce;
		size_t ReseedCounter;

		NistRngState()
			:
			Key(32, 0x00),
			Nonce(16, 0x00),
			ReseedCounter(0)
		{
		}

		~NistRngState()
		{
			ReseedCounter = 0;
			Reset();
		}

		void Reset()
		{
			MemoryTools::Clear(Key, 0, Key.size());
			MemoryTools::Clear(Nonce, 0, Nonce.size());
		}
	};

	NistRng::NistRng()
		:
		PrngBase(Prngs::None, CLASSNAME),
		m_nistRngState(new NistRngState()),
		m_rngGenerator(new ECB(Enumeration::BlockCiphers::AES))
	{
	}

	NistRng::~NistRng()
	{
		if (m_rngGenerator != nullptr)
		{
			m_rngGenerator.reset(nullptr);
		}

		if (m_nistRngState != nullptr)
		{
			m_nistRngState.reset(nullptr);
		}
	}

	const Prngs NistRng::Enumeral()
	{
		return Prngs::None;
	}

	const std::string NistRng::Name()
	{
		return CLASSNAME;
	}

	void NistRng::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
	{
		if (m_nistRngState->ReseedCounter == 0)
		{
			throw CryptoRandomException(std::string("NistRng"), std::string("Generate"), std::string("The prng has not been initialized!"), ErrorCodes::NotInitialized);
		}

		if (m_nistRngState->ReseedCounter > RNG_MAX_RESEED)
		{
			throw CryptoRandomException(std::string("NistRng"), std::string("Generate"), std::string("The prng has exceeded maximum reseed count!"), ErrorCodes::MaxExceeded);
		}

		std::vector<uint8_t> blk(m_rngGenerator->BlockSize());
		SymmetricKey kp(m_nistRngState->Key);

		// key the cipher
		m_rngGenerator->Initialize(true, kp);

		while (Length > 0)
		{
			// increment the nonce
			IntegerTools::BeIncrement8(m_nistRngState->Nonce);
			// encrypt a block
			m_rngGenerator->EncryptBlock(m_nistRngState->Nonce, 0, blk, 0);

			// copy block to output
			const size_t RMDLEN = IntegerTools::Min(blk.size(), Length);
			MemoryTools::Copy(blk, 0, Output, Offset, RMDLEN);
			Length -= RMDLEN;
			Offset += RMDLEN;
		}

		std::vector<uint8_t> zero(0);
		Update(zero, m_nistRngState->Key, m_nistRngState->Nonce);
		++m_nistRngState->ReseedCounter;
	}

	void NistRng::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
	{
		std::vector<uint8_t> tmpo(Length);
		Generate(tmpo, 0, tmpo.size());
		SecureMove(tmpo, Output, Offset);
	}

	void NistRng::Generate(std::vector<uint8_t> &Output)
	{
		Generate(Output, 0, Output.size());
	}

	void NistRng::Generate(SecureVector<uint8_t> &Output)
	{
		std::vector<uint8_t> tmpo(Output.size());
		Generate(tmpo, 0, tmpo.size());
		SecureMove(tmpo, Output, 0);
	}

	void NistRng::Initialize(const std::vector<uint8_t> &Seed)
	{
		m_nistRngState->Reset();
		Update(Seed, m_nistRngState->Key, m_nistRngState->Nonce);
		m_nistRngState->ReseedCounter = 1;
	}

	void NistRng::Initialize(const std::vector<uint8_t> &Seed, const std::vector<uint8_t> &Info)
	{
		std::vector<uint8_t> tmps(Seed.size());

		MemoryTools::Copy(Seed, 0, tmps, 0, Seed.size());

		if (Info.size() != 0)
		{
			const size_t MIXLEN = IntegerTools::Min(Info.size(), Seed.size());
			MemoryTools::XOR(Info, 0, tmps, 0, MIXLEN);
		}

		m_nistRngState->Reset();
		Update(Seed, m_nistRngState->Key, m_nistRngState->Nonce);
		m_nistRngState->ReseedCounter = 1;
	}

	uint16_t NistRng::NextUInt16()
	{
		uint16_t x;
		std::vector<uint8_t> smp(sizeof(uint16_t));

		x = 0;
		Generate(smp);
		MemoryTools::CopyToValue(smp, 0, x, sizeof(uint16_t));
		MemoryTools::Clear(smp, 0, smp.size());

		return x;
	}

	uint32_t NistRng::NextUInt32()
	{
		uint32_t x;
		std::vector<uint8_t> smp(sizeof(uint32_t));

		x = 0;
		Generate(smp);
		MemoryTools::CopyToValue(smp, 0, x, sizeof(uint32_t));
		MemoryTools::Clear(smp, 0, smp.size());

		return x;
	}

	uint64_t NistRng::NextUInt64()
	{
		uint64_t x;
		std::vector<uint8_t> smp(sizeof(uint64_t));

		x = 0;
		Generate(smp);
		MemoryTools::CopyToValue(smp, 0, x, sizeof(uint64_t));
		MemoryTools::Clear(smp, 0, smp.size());

		return x;
	}

	void NistRng::Reset()
	{
		std::vector<uint8_t> seed(RNG_SEED_SIZE);
		Provider::CSP pvd;

		pvd.Generate(seed);
		Update(seed, m_nistRngState->Key, m_nistRngState->Nonce);
	}

	void NistRng::Update(const std::vector<uint8_t> &Seed, std::vector<uint8_t> &Key, std::vector<uint8_t> &Nonce)
	{
		std::vector<uint8_t> tmps(RNG_SEED_SIZE);
		size_t i;

		// key the cipher
		SymmetricKey kp(Key);
		m_rngGenerator->Initialize(true, kp);

		for (i = 0; i < 3; i++)
		{
			// increment big-endian counter
			IntegerTools::BeIncrement8(Nonce);
			// encrypt a block
			m_rngGenerator->EncryptBlock(Nonce, 0, tmps, i * m_rngGenerator->BlockSize());
		}

		if (Seed.size() != 0)
		{
			// xor the new seed material to the key and nonce
			MemoryTools::XOR(Seed, 0, tmps, 0, tmps.size());
		}

		// copy the new key and nonce to state
		MemoryTools::Copy(tmps, 0, Key, 0, Key.size());
		MemoryTools::Copy(tmps, Key.size(), Nonce, 0, Nonce.size());
	}
}
