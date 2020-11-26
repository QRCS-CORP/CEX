#include "KPA.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#if defined(CEX_HAS_AVX512)
#	include "ULong512.h"
#elif defined(CEX_HAS_AVX2)
#	include "ULong256.h"
#endif

NAMESPACE_MAC

using Tools::IntegerTools;
using Digest::Keccak;
using Enumeration::MacConvert;
using Tools::MemoryTools;
using Enumeration::KbaModeConvert;
#if defined(CEX_HAS_AVX512)
	using Numeric::ULong512;
#elif defined(CEX_HAS_AVX2)
	using Numeric::ULong256;
#endif

class KPA::KpaState
{
public:

#if defined(CEX_HAS_AVX512)
	std::array<ULong512, Keccak::KECCAK_STATE_SIZE> StateW;
#elif defined(CEX_HAS_AVX2)
	std::vector<std::array<ULong256, Keccak::KECCAK_STATE_SIZE>> StateW;
#endif
	std::vector<std::array<ulong, Keccak::KECCAK_STATE_SIZE>> State;
	std::vector<byte> Buffer;
	size_t Rate;
	size_t MacSize;
	size_t Position;
	size_t Processed;
	KpaModes KmacMode;
	bool IsInitialized;

	KpaState(size_t InputSize, size_t OutputSize, KpaModes Mode)
		:
#if defined(CEX_HAS_AVX2)  && !defined(CEX_HAS_AVX512)
		StateW(2),
#endif
		State(8),
		Buffer(KPA_PARALLELISM * Keccak::KECCAK_STATE_SIZE * sizeof(uint64_t)),
		Rate(InputSize),
		MacSize(OutputSize),
		Position(0),
		Processed(0),
		KmacMode(Mode),
		IsInitialized(false)
	{
	}

	~KpaState()
	{
		Rate = 0;
		MacSize = 0;
		Position = 0;
		Processed = 0;
		KmacMode = KpaModes::None;

#if defined(CEX_HAS_AVX512)
		MemoryTools::Clear(StateW, 0, StateW.size() * sizeof(ULong512));
#elif defined(CEX_HAS_AVX2)
		MemoryTools::Clear(StateW[0], 0, StateW[0].size() * sizeof(ULong256));
		MemoryTools::Clear(StateW[1], 0, StateW[1].size() * sizeof(ULong256));
#endif

		for (size_t i = 0; i < State.size(); ++i)
		{
			MemoryTools::Clear(State[i], 0, State[i].size());
		}

		MemoryTools::Clear(Buffer, 0, Buffer.size());
	}

	void Reset()
	{
		Position = 0;
		Processed = 0;

#if defined(CEX_HAS_AVX512)
		MemoryTools::Clear(StateW, 0, StateW.size() * sizeof(ULong512));
#elif defined(CEX_HAS_AVX2)
		MemoryTools::Clear(StateW[0], 0, StateW[0].size() * sizeof(ULong256));
		MemoryTools::Clear(StateW[1], 0, StateW[1].size() * sizeof(ULong256));
#endif

		for (size_t i = 0; i < State.size(); ++i)
		{
			MemoryTools::Clear(State[i], 0, State[i].size());
		}

		MemoryTools::Clear(Buffer, 0, Buffer.size());
	}
};

//~~~Constructor~~~//

KPA::KPA(KpaModes KbaModeType)
	:
	MacBase(
		(KbaModeType == KpaModes::KPA128 ? Keccak::KECCAK128_RATE_SIZE :
			KbaModeType == KpaModes::KPA256 ? Keccak::KECCAK256_RATE_SIZE :
			KbaModeType == KpaModes::KPA512 ? Keccak::KECCAK512_RATE_SIZE : 0),
		static_cast<Macs>(KbaModeType),
		KbaModeConvert::ToName(KbaModeType),
		std::vector<SymmetricKeySize> { 
			SymmetricKeySize((KbaModeType == KpaModes::KPA128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KbaModeType == KpaModes::KPA256 ? Keccak::KECCAK256_DIGEST_SIZE :
			Keccak::KECCAK512_DIGEST_SIZE), 0, 0)},
		16,
		0,
		(KbaModeType == KpaModes::KPA128 ? Keccak::KECCAK128_DIGEST_SIZE :
			KbaModeType == KpaModes::KPA256 ? Keccak::KECCAK256_DIGEST_SIZE :
			KbaModeType == KpaModes::KPA512)),
	m_kbaState(KbaModeType != KpaModes::None ? new KpaState(BlockSize(), TagSize(), KbaModeType) :
		throw CryptoMacException(std::string("KPA"), std::string("Constructor"), std::string("The kmac mode type is not supported!"), ErrorCodes::InvalidParam))
{
}

	KPA::~KPA()
	{
		if (m_kbaState != nullptr)
		{
			m_kbaState.reset(nullptr);
		}
	}

	//~~~Accessors~~~//

	const size_t KPA::DistributionCodeMax()
	{
		return BlockSize();
	}

	const bool KPA::IsInitialized()
	{
		return m_kbaState->IsInitialized;
	}

	const KpaModes KPA::KbaMode()
	{
		return m_kbaState->KmacMode;
	}

	//~~~Public Functions~~~//

	void KPA::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
	{
		if (IsInitialized() == false)
		{
			throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
		}
		if (Output.size() < TagSize())
		{
			throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
		}

		Update(Input, 0, Input.size());
		Finalize(Output, 0);
	}

	size_t KPA::Finalize(std::vector<byte> &Output, size_t OutOffset)
	{
		SecureVector<byte> tmph(Output.size() - OutOffset);

		Finalize(tmph, 0);
		SecureMove(tmph, 0, Output, OutOffset, tmph.size());

		return tmph.size();
	}

	size_t KPA::Finalize(SecureVector<byte> &Output, size_t OutOffset)
	{
		if (IsInitialized() == false)
		{
			throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
		}
		if ((Output.size() - OutOffset) < TagSize())
		{
			throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
		}
		if (m_kbaState->Position != m_kbaState->Buffer.size())
		{
			MemoryTools::Clear(m_kbaState->Buffer, m_kbaState->Position, m_kbaState->Buffer.size() - m_kbaState->Position);
		}

		const size_t HASHLEN = (m_kbaState->Rate == Keccak::KECCAK128_RATE_SIZE) ?
			KPA_LEAF_HASH512 : (m_kbaState->Rate == Keccak::KECCAK256_RATE_SIZE) ?
			KPA_LEAF_HASH256 : KPA_LEAF_HASH512;

		std::vector<byte> fbuf(KPA_PARALLELISM * KPA_LEAF_HASH512);
		std::vector<ulong> pstate(Keccak::KECCAK_STATE_SIZE);
		std::vector<byte> prcb(2 * sizeof(uint64_t));
		size_t bitlen;
		size_t i;
		size_t outlen;
		size_t outoft;

		outlen = Output.size();
		outoft = 0;

		// clear unused buffer
		if (m_kbaState->Position != 0)
		{
			MemoryTools::Clear(m_kbaState->Buffer, m_kbaState->Position, m_kbaState->Buffer.size() - m_kbaState->Position);
			FastAbsorbx8(m_kbaState, m_kbaState->Buffer, 0);
			KpaPermutex8(m_kbaState);
		}

		// set processed counter to final position
		m_kbaState->Processed += m_kbaState->Position;

#if defined(CEX_KPA_AVX_PARALLEL)
		KpaStoreState(m_kbaState);
#endif

		// collect leaf node hashes
		for (i = 0; i < KPA_PARALLELISM; ++i)
		{
			// copy each of the leaf hashes to the buffer
			MemoryTools::Copy(m_kbaState->State[i], 0, fbuf, i * HASHLEN, HASHLEN);
		}

		// absorb the leaves into the root state and permute
		KpaAbsorbLeaves(pstate, m_kbaState->Rate, fbuf, 0, KPA_PARALLELISM * HASHLEN);

		// clear buffer
		MemoryTools::Clear(m_kbaState->Buffer, 0, m_kbaState->Buffer.size());

		// add total processed bytes and output length to padding string
		bitlen = Keccak::RightEncode(prcb, 0, 8ULL * Output.size());
		bitlen += Keccak::RightEncode(prcb, bitlen, 8ULL * m_kbaState->Processed);
		// copy to buffer
		MemoryTools::Copy(prcb, 0, m_kbaState->Buffer, 0, bitlen);

		// add the domain id
		m_kbaState->Buffer[bitlen] = Keccak::KECCAK_KPA_DOMAIN_ID;
		// clamp the last byte
		m_kbaState->Buffer[m_kbaState->Rate - 1] |= 128U;

		// absorb the buffer into parent state
		Keccak::FastAbsorb(m_kbaState->Buffer, 0, m_kbaState->Rate, pstate);

		// squeeze blocks to produce the output hash
		while (outlen >= m_kbaState->Rate)
		{
			KpaSqueezeBlocks(pstate, m_kbaState->Buffer, 1, m_kbaState->Rate);
			MemoryTools::Copy(m_kbaState->Buffer, 0, Output, outoft, m_kbaState->Rate);
			outoft += m_kbaState->Rate;
			outlen -= m_kbaState->Rate;
		}

		// add unaligned hash bytes
		if (outlen > 0)
		{
			KpaSqueezeBlocks(pstate, m_kbaState->Buffer, 1, m_kbaState->Rate);
			MemoryTools::Copy(m_kbaState->Buffer, 0, Output, outoft, outlen);
		}

		// reset the buffer and counters
		MemoryTools::Clear(m_kbaState->Buffer, 0, m_kbaState->Buffer.size());
		m_kbaState->Position = 0;
		m_kbaState->Processed = 0;

		return Output.size();
	}

	void KPA::Initialize(ISymmetricKey &Parameters)
	{
#if defined(CEX_ENFORCE_LEGALKEY)
		if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
		{
			throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
		}
#else
		if (Parameters.KeySizes().KeySize() < MinimumKeySize())
		{
			throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
		}
#endif

		if (Parameters.KeySizes().IVSize() != 0 && Parameters.KeySizes().IVSize() < MinimumSaltSize())
		{
			throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid salt size, must be at least MinimumSaltSize in length!"), ErrorCodes::InvalidSalt);
		}

		if (IsInitialized() == true)
		{
			Reset();
		}

		std::array<ulong, Keccak::KECCAK_STATE_SIZE> tmps = { 0 };
		std::vector<byte> pad(Keccak::KECCAK_STATE_SIZE * sizeof(ulong));
		std::vector<byte> algb = { 0x00, 0x00, 0x4B, 0x42, 0x41, 0xAD, 0x31, 0x32 };
		std::vector<byte> cust;
		std::vector<byte> key;

		ulong algn;
		size_t oft;
		size_t i;

		// set state values
		m_kbaState->Position = 0;
		m_kbaState->Processed = 0;
		m_kbaState->Rate = (Parameters.KeySizes().KeySize() == KPA_128_KEY_SIZE) ?
			Keccak::KECCAK128_RATE_SIZE : (Parameters.KeySizes().KeySize() == KPA_256_KEY_SIZE) ?
			Keccak::KECCAK256_RATE_SIZE : Keccak::KECCAK512_RATE_SIZE;

		if (m_kbaState->IsInitialized)
		{
			for (i = 0; i < m_kbaState->State.size(); ++i)
			{
				MemoryTools::Clear(m_kbaState->State[i], 0, m_kbaState->State[i].size());
			}

			MemoryTools::Clear(m_kbaState->Buffer, 0, sizeof(m_kbaState->Buffer));
		}

		// stage 1: add customization to state

		if (Parameters.KeySizes().IVSize() != 0)
		{
			cust = Parameters.IV();
			oft = Keccak::LeftEncode(pad, 0, m_kbaState->Rate);
			oft += Keccak::LeftEncode(pad, oft, 8ULL * Parameters.KeySizes().IVSize());

			for (i = 0; i < Parameters.KeySizes().IVSize(); ++i)
			{
				if (oft == m_kbaState->Rate)
				{
					Keccak::FastAbsorb(pad, 0, m_kbaState->Rate, tmps);
					Keccak::PermuteR24P1600C(tmps, KPA_ROUNDS);
					oft = 0;
				}

				pad[oft] = cust[i];
				++oft;
			}

			if (oft != 0)
			{
				// absorb custom and name, and permute state
				MemoryTools::Clear(pad, oft, m_kbaState->Rate - oft);
				Keccak::FastAbsorb(pad, 0, m_kbaState->Rate, tmps);
				Keccak::PermuteR24P1600C(tmps, KPA_ROUNDS);
			}
		}

		// stage 2: add key to state

		if (Parameters.KeySizes().KeySize())
		{
			key = Parameters.Key();
			MemoryTools::Clear(pad, 0, m_kbaState->Rate);
			oft = Keccak::LeftEncode(pad, 0, m_kbaState->Rate);
			oft += Keccak::LeftEncode(pad, oft, 8ULL * Parameters.KeySizes().KeySize());

			for (i = 0; i < Parameters.KeySizes().KeySize(); ++i)
			{
				if (oft == m_kbaState->Rate)
				{
					Keccak::FastAbsorb(pad, 0, m_kbaState->Rate, tmps);
					Keccak::PermuteR24P1600C(tmps, KPA_ROUNDS);
					oft = 0;
				}

				pad[oft] = key[i];
				++oft;
			}

			if (oft != 0)
			{
				// absorb the key and permute the state
				MemoryTools::Clear(pad, oft, m_kbaState->Rate - oft);
				Keccak::FastAbsorb(pad, 0, m_kbaState->Rate, tmps);
				Keccak::PermuteR24P1600C(tmps, KPA_ROUNDS);
			}
		}

		// stage 3: copy state to leaf nodes, and add leaf-unique name string


#if defined(CEX_HAS_AVX512)

		std::vector<ulong> tmpi(8);

		for (i = 1; i < Keccak::KECCAK_STATE_SIZE; ++i)
		{
			m_kbaState->StateW[i] = ULong512(tmps[i]);
		}

		for (i = 0; i < KPA_PARALLELISM; ++i)
		{
			// store the state index to the algorithm name
			IntegerTools::Be16ToBytes((static_cast<uint16_t>(i) + 1), algb, 0);
			// copy the name to a 64-bit integer
			algn = IntegerTools::BeBytesTo64(algb, 0);
			// absorb the leafs unique index name
			tmpi[i] = tmps[0] ^ algn;
		}

		m_kbaState->StateW[0] = ULong512(tmpi, 0);

#elif defined(CEX_HAS_AVX2)

		std::vector<ulong> tmpi(8);

		for (i = 1; i < Keccak::KECCAK_STATE_SIZE; ++i)
		{
			m_kbaState->StateW[0][i] = ULong256(tmps[i]);
			m_kbaState->StateW[1][i] = ULong256(tmps[i]);
		}

		for (i = 0; i < KPA_PARALLELISM; ++i)
		{
			// store the state index to the algorithm name
			IntegerTools::Be16ToBytes((static_cast<uint16_t>(i) + 1), algb, 0);
			// copy the name to a 64-bit integer
			algn = IntegerTools::BeBytesTo64(algb, 0);
			// absorb the leafs unique index name
			tmpi[i] = tmps[0] ^ algn;
		}

		m_kbaState->StateW[0][0] = ULong256(tmpi, 0);
		m_kbaState->StateW[1][0] = ULong256(tmpi, 4);

#else

		for (i = 0; i < KPA_PARALLELISM; ++i)
		{
			// store the state index to the algorithm name
			IntegerTools::Be16ToBytes((static_cast<uint16_t>(i) + 1), algb, 0);
			// copy the name to a 64-bit integer
			algn = IntegerTools::BeBytesTo64(algb, 0);
			// copy the state to each leaf node
			MemoryTools::Copy(tmps, 0, m_kbaState->State[i], 0, sizeof(tmps));
			// absorb the leafs unique index name
			m_kbaState->State[i][0] ^= algn;
		}

#endif

		// permute leaf nodes
		KpaPermutex8(m_kbaState);
		m_kbaState->IsInitialized = true;
	}

	void KPA::Reset()
	{
		m_kbaState->Reset();
		m_kbaState->IsInitialized = false;
	}

	void KPA::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
	{
		if (IsInitialized() == false)
		{
			throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
		}
		if ((Input.size() - InOffset) < Length)
		{
			throw CryptoMacException(Name(), std::string("Update"), std::string("The Input buffer is too short!"), ErrorCodes::InvalidSize);
		}

		if (Length != 0)
		{
			const size_t BLKLEN = m_kbaState->Rate * KPA_PARALLELISM;

			if (m_kbaState->Position != 0 && (m_kbaState->Position + Length >= BLKLEN))
			{
				const size_t RMDLEN = BLKLEN - m_kbaState->Position;

				if (RMDLEN != 0)
				{
					MemoryTools::Copy(Input, InOffset, m_kbaState->Buffer, m_kbaState->Position, RMDLEN);
				}

				FastAbsorbx8(m_kbaState, m_kbaState->Buffer, 0);
				KpaPermutex8(m_kbaState);
				m_kbaState->Processed += m_kbaState->Rate * KPA_PARALLELISM;
				m_kbaState->Position = 0;
				InOffset += RMDLEN;
				Length -= RMDLEN;
			}

			// sequential loop through blocks
			while (Length >= BLKLEN)
			{
				FastAbsorbx8(m_kbaState, Input, InOffset);
				KpaPermutex8(m_kbaState);
				m_kbaState->Processed += m_kbaState->Rate * KPA_PARALLELISM;
				InOffset += BLKLEN;
				Length -= BLKLEN;
			}

			// store unaligned bytes
			if (Length != 0)
			{
				MemoryTools::Copy(Input, InOffset, m_kbaState->Buffer,  m_kbaState->Position, Length);
				m_kbaState->Position += Length;
			}
		}
	}

	//~~~Private Functions~~~//
	
	void KPA::FastAbsorbx8(std::unique_ptr<KpaState> &Ctx, const std::vector<byte> &Input, size_t InOffset)
	{
		size_t i;

#if defined(CEX_HAS_AVX512)

		const size_t ROFT = Ctx->Rate;
		__m512i idx;
		ULong512 wbuf;
		size_t pos;

		idx = _mm512_set_epi64((int64_t)&Input[InOffset + (7 * ROFT)], (int64_t)&Input[InOffset + (6 * ROFT)], 
			(int64_t)&Input[InOffset + (5 * ROFT)], (int64_t)&Input[InOffset + (4 * ROFT)], 
			(int64_t)&Input[InOffset + (3 * ROFT)], (int64_t)&Input[InOffset + (2 * ROFT)], 
			(int64_t)&Input[InOffset + (ROFT)], (int64_t)&Input[InOffset]);

		pos = 0;

		for (i = 0; i < Ctx->Rate / sizeof(uint64_t); ++i)
		{
			wbuf = ULong512(_mm512_i64gather_epi64(idx, (int64_t*)pos, 1));
			pos += sizeof(ulong);
			Ctx->StateW[i] ^= wbuf;
		}

#elif defined(CEX_HAS_AVX2)

		const size_t ROFT = Ctx->Rate;
		std::vector<ulong> tmp(4);

		for (i = 0; i < Ctx->Rate / sizeof(uint64_t); ++i)
		{
			tmp[0] = IntegerTools::LeBytesTo64(Input, InOffset);
			tmp[1] = IntegerTools::LeBytesTo64(Input, InOffset + ROFT);
			tmp[2] = IntegerTools::LeBytesTo64(Input, InOffset + (2 * ROFT));
			tmp[3] = IntegerTools::LeBytesTo64(Input, InOffset + (3 * ROFT));
			ULong256 x1(tmp, 0);
			Ctx->StateW[0][i] ^= x1;

			tmp[0] = IntegerTools::LeBytesTo64(Input, InOffset + (4 * ROFT));
			tmp[1] = IntegerTools::LeBytesTo64(Input, InOffset + (5 * ROFT));
			tmp[2] = IntegerTools::LeBytesTo64(Input, InOffset + (6 * ROFT));
			tmp[3] = IntegerTools::LeBytesTo64(Input, InOffset + (7 * ROFT));
			ULong256 x2(tmp, 0);
			Ctx->StateW[1][i] ^= x2;
			InOffset += sizeof(ulong);
		}

#else

		for (size_t i = 0; i < KPA_PARALLELISM; ++i)
		{
#if defined(CEX_IS_LITTLE_ENDIAN)
			MemoryTools::XOR(Input, InOffset + (i * Ctx->Rate), Ctx->State[i], 0, Ctx->Rate);
#else
			for (size_t j = 0; j < Ctx->Rate / sizeof(uint64_t); ++j)
			{
				Ctx->State[i][j] ^= IntegerTools::LeBytesTo64(Input, InOffset + (i * Ctx->Rate) + (j * sizeof(uint64_t)));
			}
#endif
		}
#endif
	}

	void KPA::KpaAbsorbLeaves(std::vector<ulong> &State, size_t Rate, const std::vector<byte> &Input, size_t InOffset, size_t Length)
	{
		while (Length >= Rate)
		{
#if defined(CEX_IS_LITTLE_ENDIAN)
			MemoryTools::XOR(Input, InOffset, State, 0, Rate);
#else
			for (size_t i = 0; i < Rate / sizeof(uint64_t); ++i)
			{
				State[i] ^= IntegerTools::LeBytesTo64(Input, (sizeof(uint64_t) * i));
			}
#endif
			Keccak::PermuteR24P1600C(State, KPA_ROUNDS);
			Length -= Rate;
			InOffset += Rate;
		}

		if (Length != 0)
		{
#if defined(CEX_IS_LITTLE_ENDIAN)
			MemoryTools::XOR(Input, InOffset, State, 0, Length);
#else
			for (size_t i = 0; i < Length / sizeof(uint64_t); ++i)
			{
				State[i] ^= IntegerTools::LeBytesTo64(Input, (sizeof(uint64_t) * i));
			}
#endif

			Keccak::PermuteR24P1600C(State, KPA_ROUNDS);
		}
	}

	void KPA::KpaLoadState(std::unique_ptr<KpaState> &Ctx)
	{
		size_t i;

#if defined(CEX_HAS_AVX512)

		__m512i idx;
		size_t pos;

		idx = _mm512_set_epi64((int64_t)&Ctx->State[7][0], (int64_t)&Ctx->State[6][0], (int64_t)&Ctx->State[5][0], (int64_t)&Ctx->State[4][0],
			(int64_t)&Ctx->State[3][0], (int64_t)&Ctx->State[2][0], (int64_t)&Ctx->State[1][0], (int64_t)&Ctx->State[0][0]);

		pos = 0;

		for (i = 0; i < Keccak::KECCAK_STATE_SIZE; ++i)
		{
			Ctx->StateW[i] = ULong512(_mm512_i64gather_epi64(idx, (int64_t*)pos, 1));
			pos += sizeof(uint64_t);
		}

#elif defined(CEX_HAS_AVX2)

		uint64_t tmp[4] = { 0 };

		for (i = 0; i < Keccak::KECCAK_STATE_SIZE; ++i)
		{
			tmp[0] = Ctx->State[0][i];
			tmp[1] = Ctx->State[1][i];
			tmp[2] = Ctx->State[2][i];
			tmp[3] = Ctx->State[3][i];
			Ctx->StateW[0][i] = ULong256(tmp, 0);
			tmp[0] = Ctx->State[4][i];
			tmp[1] = Ctx->State[5][i];
			tmp[2] = Ctx->State[6][i];
			tmp[3] = Ctx->State[7][i];
			Ctx->StateW[1][i] = ULong256(tmp, 4);
		}
#endif
	}

	void KPA::KpaPermutex8(std::unique_ptr<KpaState> &Ctx)
	{
#if defined(CEX_HAS_AVX512)
		Keccak::PermuteR24P8x1600H(Ctx->StateW, KPA_ROUNDS);
#elif defined(CEX_HAS_AVX2)
		Keccak::PermuteR24P4x1600H(Ctx->StateW[0], KPA_ROUNDS);
		Keccak::PermuteR24P4x1600H(Ctx->StateW[1], KPA_ROUNDS);
#else
		for (size_t i = 0; i < KPA_PARALLELISM; ++i)
		{
			Keccak::PermuteR24P1600C(Ctx->State[i], KPA_ROUNDS);
		}
#endif
	}

	void KPA::KpaSqueezeBlocks(std::vector<ulong> &State, std::vector<byte> &Output, size_t BlockCount, size_t Rate)
	{
		size_t oft;

		oft = 0;

		while (BlockCount > 0)
		{
			Keccak::PermuteR24P1600C(State, KPA_ROUNDS);

#if defined(CEX_IS_LITTLE_ENDIAN)
			MemoryTools::Copy(State, 0, Output, oft, Rate);
#else
			for (size_t i = 0; i < (Rate >> 3); ++i)
			{
				IntegerTools::Le64ToBytes(State[i], Output, i * sizeof(ulong));
			}
#endif
			oft += Rate;
			--BlockCount;
		}
	}

	void KPA::KpaStoreState(std::unique_ptr<KpaState> &Ctx)
	{
		size_t i;

#if defined(CEX_HAS_AVX512)

		std::vector<ulong> tmp(8);

		for (i = 0; i < Keccak::KECCAK_STATE_SIZE; ++i)
		{
			Ctx->StateW[i].Store(tmp, 0);
			Ctx->State[0][i] = tmp[0];
			Ctx->State[1][i] = tmp[1];
			Ctx->State[2][i] = tmp[2];
			Ctx->State[3][i] = tmp[3];
			Ctx->State[4][i] = tmp[4];
			Ctx->State[5][i] = tmp[5];
			Ctx->State[6][i] = tmp[6];
			Ctx->State[7][i] = tmp[7];
		}

#elif defined(CEX_HAS_AVX2)

		std::vector<ulong> tmp(4);

		for (i = 0; i < Keccak::KECCAK_STATE_SIZE; ++i)
		{
			Ctx->StateW[0][i].Store(tmp, 0);
			Ctx->State[0][i] = tmp[0];
			Ctx->State[1][i] = tmp[1];
			Ctx->State[2][i] = tmp[2];
			Ctx->State[3][i] = tmp[3];
			Ctx->StateW[1][i].Store(tmp, 0);
			Ctx->State[4][i] = tmp[0];
			Ctx->State[5][i] = tmp[1];
			Ctx->State[6][i] = tmp[2];
			Ctx->State[7][i] = tmp[3];
		}

#endif
	}

	NAMESPACE_MACEND
