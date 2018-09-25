#include "CSG.h"
#include "CpuDetect.h"
#include "IntUtils.h"
#include "ParallelUtils.h"
#include "ProviderFromName.h"
#include "SymmetricKey.h"

#include "ULong256.h"

NAMESPACE_DRBG

using Utility::IntUtils;
using Utility::MemUtils;
using Numeric::ULong256;

const std::string CSG::CLASS_NAME("CSG");

//~~~Constructor~~~//

CSG::CSG(ShakeModes ShakeModeType, Providers ProviderType, bool Parallel)
	:
#if !defined(__AVX2__) && !defined(__AVX512__)
	m_avxEnabled(false),
#else
	m_avxEnabled(Parallel),
#endif
	m_blockSize((ShakeModeType == ShakeModes::SHAKE128) ? 168 : (ShakeModeType == ShakeModes::SHAKE256) ? 136 : 72),
	m_bufferIndex(0),
	m_customNonce(0),
	m_destroyEngine(true),
	m_distCode(0),
	m_distCodeMax(0),
	m_domainCode(SHAKE_DOMAIN),
	m_drbgBuffer(m_blockSize),
	m_drbgState(1),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(ProviderType != Providers::None),
	m_providerSource(ProviderType == Providers::None ? nullptr : Helper::ProviderFromName::GetInstance(ProviderType)),
	m_providerType(ProviderType),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_blockSize * 10000),
	m_secStrength((ShakeModeType == ShakeModes::SHAKE128) ? 128 : (ShakeModeType == ShakeModes::SHAKE256) ? 256 : (ShakeModeType == ShakeModes::SHAKE512) ? 512 : 1024),
	m_seedSize(0),
	m_shakeMode(ShakeModeType == ShakeModes::SHAKE128 || ShakeModeType == ShakeModes::SHAKE256 || ShakeModeType == ShakeModes::SHAKE512 || ShakeModeType == ShakeModes::SHAKE1024 ? ShakeModeType :
		throw CryptoGeneratorException("CSG:Ctor", "The SHAKE mode type is invalid!")),
	m_stateSize(STATE_SIZE)
{
	Scope();
}

CSG::CSG(ShakeModes ShakeModeType, IProvider* Provider, bool Parallel)
	:
#if !defined(__AVX2__) && !defined(__AVX512__)
	m_avxEnabled(false),
#else
	m_avxEnabled(Parallel),
#endif
	m_blockSize((ShakeModeType == ShakeModes::SHAKE128) ? 168 : (ShakeModeType == ShakeModes::SHAKE256) ? 136 : 72),
	m_bufferIndex(0),
	m_customNonce(0),
	m_destroyEngine(false),
	m_distCode(0),
	m_distCodeMax(0),
	m_domainCode(SHAKE_DOMAIN),
	m_drbgBuffer(m_blockSize),
	m_drbgState(1),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_prdResistant(Provider != nullptr),
	m_providerSource(Provider),
	m_providerType(m_providerSource != nullptr ? m_providerSource->Enumeral() : Providers::None),
	m_reseedCounter(0),
	m_reseedRequests(0),
	m_reseedThreshold(m_blockSize * 10000),
	m_secStrength((ShakeModeType == ShakeModes::SHAKE128) ? 128 : (ShakeModeType == ShakeModes::SHAKE256) ? 256 : 512),
	m_seedSize(0),
	m_shakeMode(ShakeModeType != ShakeModes::None ? ShakeModeType :
		throw CryptoGeneratorException("CSG:Ctor", "The SHAKE mode type can not ne none!")),
	m_stateSize(STATE_SIZE)
{
	Scope();
}

CSG::~CSG()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_avxEnabled = false;
		m_blockSize = 0;
		m_bufferIndex = 0;
		m_distCodeMax = 0;
		m_isInitialized = false;
		m_prdResistant = false;
		m_providerType = Providers::None;
		m_reseedCounter = 0;
		m_reseedRequests = 0;
		m_reseedThreshold = 0;
		m_secStrength = 0;
		m_seedSize = 0;
		m_shakeMode = ShakeModes::None;
		m_stateSize = 0;

		for (size_t i = 0; i < m_drbgState.size(); ++i)
		{
			IntUtils::ClearArray(m_drbgState[i]);
		}

		IntUtils::ClearVector(m_drbgBuffer);
		IntUtils::ClearVector(m_drbgState);
		IntUtils::ClearVector(m_customNonce);
		IntUtils::ClearVector(m_distCode);
		IntUtils::ClearVector(m_legalKeySizes);

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_providerSource != nullptr)
			{
				m_providerSource.reset(nullptr);
			}
		}
		else
		{
			if (m_providerSource != nullptr)
			{
				m_providerSource.release();
			}
		}
	}
}

//~~~Accessors~~~//

std::vector<byte> &CSG::DistributionCode()
{
	return m_distCode;
}

const size_t CSG::DistributionCodeMax()
{
	return m_distCodeMax;
}

const Drbgs CSG::Enumeral()
{
	return Drbgs::CSG;
}

const bool CSG::IsInitialized()
{
	return m_isInitialized;
}

std::vector<SymmetricKeySize> CSG::LegalKeySizes() const
{
	return m_legalKeySizes;
}

const ulong CSG::MaxOutputSize()
{
	return MAX_OUTPUT;
}

const size_t CSG::MaxRequestSize()
{
	return MAX_REQUEST;
}

const size_t CSG::MaxReseedCount()
{
	return MAX_RESEED;
}

const std::string CSG::Name()
{
	return CLASS_NAME + "-" + IntUtils::ToString(m_secStrength);
}

const size_t CSG::NonceSize()
{
	return m_distCodeMax / 2;
}

size_t &CSG::ReseedThreshold()
{
	return m_reseedThreshold;
}

const size_t CSG::SecurityStrength()
{
	return m_secStrength;
}

//~~~Public Functions~~~//

size_t CSG::Generate(std::vector<byte> &Output)
{
	return Generate(Output, 0, Output.size());
}

size_t CSG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert((Output.size() - Length) >= OutOffset, "Output buffer too small!");

	if (!m_isInitialized)
	{
		throw CryptoGeneratorException("CSG:Generate", "The generator has been reset, or was not initialized!");
	}

	Extract(Output, OutOffset, Length);

	if (m_prdResistant)
	{
		m_reseedCounter += Length;

		if (m_reseedCounter >= m_reseedThreshold)
		{
			++m_reseedRequests;

			if (m_reseedRequests > MAX_RESEED)
			{
				throw CryptoGeneratorException("CSG:Generate", "The maximum reseed requests can not be exceeded, re-initialize the generator!");
			}

			Derive();
			m_reseedCounter = 0;
		}
	}

	return Length;
}

void CSG::Initialize(ISymmetricKey &GenParam)
{
	if (GenParam.Nonce().size() != 0)
	{
		if (GenParam.Info().size() != 0)
		{
			Initialize(GenParam.Key(), GenParam.Nonce(), GenParam.Info());
		}
		else
		{
			Initialize(GenParam.Key(), GenParam.Nonce());
		}
	}
	else
	{
		Initialize(GenParam.Key());
	}
}

void CSG::Initialize(const std::vector<byte> &Seed)
{
	if (m_isInitialized)
	{
		Reset();
	}

	if (!m_avxEnabled)
	{
		Customize(m_customNonce, m_distCode, m_drbgState[0]);
		Permute(m_drbgState[0]);
		FastAbsorb(Seed, 0, Seed.size(), m_drbgState[0]);
		Fill();
	}
	else
	{
		// count block bits
		const size_t CTRIVL = m_blockSize * 8;
		const size_t CSTLEN = m_customNonce.size() + sizeof(ushort);
		std::vector<byte> ctr(CSTLEN);

		// add customization string to start of counter
		MemUtils::Copy(m_customNonce, 0, ctr, 0, m_customNonce.size());

		// loop through state members, initializing each to a unique set of values
		for (size_t i = 0; i < m_drbgState.size(); ++i)
		{
			IntUtils::BeIncrease8(ctr, CTRIVL * (i + 1));
			Customize(ctr, m_distCode, m_drbgState[i]);
		}

		// permute customizations
		PermuteW(m_drbgState);

		// add the seed
		for (size_t i = 0; i < m_drbgState.size(); ++i)
		{
			FastAbsorb(Seed, 0, Seed.size(), m_drbgState[i]);
		}

		// seed permutation, then fill the buffer
		Fill();
	}

	m_seedSize = Seed.size();
	m_isInitialized = true;
}

void CSG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce)
{
	if (m_isInitialized)
	{
		Reset();
	}

	m_customNonce = Nonce;

	Initialize(Seed);
}

void CSG::Initialize(const std::vector<byte> &Seed, const std::vector<byte> &Nonce, const std::vector<byte> &Info)
{
	if (m_isInitialized)
	{
		Reset();
	}

	m_customNonce = Nonce;
	m_distCode = Info;

	Initialize(Seed);
}

void CSG::Update(const std::vector<byte> &Seed)
{
	// add new entropy equal to original key size to the state
	for (size_t i = 0; i < m_drbgState.size(); ++i)
	{
		FastAbsorb(Seed, 0, Seed.size(), m_drbgState[i]);
	}

	Fill();
}

//~~~Private Functions~~~//

void CSG::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name, std::array<ulong, STATE_SIZE> &State)
{
	CexAssert(Customization.size() + Name.size() <= 196, "the input buffer is too large");

	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	size_t offset;

	offset = 0;
	offset = LeftEncode(pad, 0, m_blockSize);
	offset += LeftEncode(pad, offset, Name.size() * 8);

	m_domainCode = CSHAKE_DOMAIN;

	if (Name.size() != 0)
	{
		for (i = 0; i < Name.size(); i++)
		{
			if (offset == m_blockSize)
			{
				for (size_t i = 0; i < BUFFER_SIZE; i += 8)
				{
					State[i / 8] ^= IntUtils::LeBytesTo64(pad, i);
				}

				Permute(State);
				offset = 0;
			}

			pad[offset] = Name[i];
			++offset;
		}
	}

	offset += LeftEncode(pad, offset, Customization.size() * 8);

	if (Customization.size() != 0)
	{
		for (i = 0; i < Customization.size(); i++)
		{
			if (offset == m_blockSize)
			{
				for (size_t i = 0; i < BUFFER_SIZE; i += 8)
				{
					State[i / 8] ^= IntUtils::LeBytesTo64(pad, i);
				}

				Permute(State);
				offset = 0;
			}

			pad[offset] = Customization[i];
			++offset;
		}
	}

	MemUtils::Clear(pad, offset, BUFFER_SIZE - offset);
	offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));

	for (size_t i = 0; i < offset; i += 8)
	{
		State[i / 8] ^= IntUtils::LeBytesTo64(pad, i);
	}
}

void CSG::Derive()
{
	std::vector<byte> seed(m_seedSize);

	// add new entropy equal to original key size to the state
	for (size_t i = 0; i < m_drbgState.size(); ++i)
	{
		m_providerSource->Generate(seed);
		FastAbsorb(seed, 0, seed.size(), m_drbgState[i]);
	}

	Fill();
}

void CSG::Extract(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(Output.size() != 0, "output size must be at least 1 in length");

	if (m_drbgBuffer.size() - m_bufferIndex < Length)
	{
		size_t bufPos = m_drbgBuffer.size() - m_bufferIndex;

		// copy remaining bytes
		if (bufPos != 0)
		{
			Utility::MemUtils::Copy(m_drbgBuffer, m_bufferIndex, Output, OutOffset, bufPos);
		}

		size_t prcLen = Length - bufPos;

		while (prcLen > 0)
		{
			// re-fill the buffer
			Fill();

			if (prcLen > m_drbgBuffer.size())
			{
				Utility::MemUtils::Copy(m_drbgBuffer, 0, Output, OutOffset + bufPos, m_drbgBuffer.size());
				bufPos += m_drbgBuffer.size();
				prcLen -= m_drbgBuffer.size();
			}
			else
			{
				Utility::MemUtils::Copy(m_drbgBuffer, 0, Output, OutOffset + bufPos, prcLen);
				m_bufferIndex = prcLen;
				prcLen = 0;
			}
		}
	}
	else
	{
		Utility::MemUtils::Copy(m_drbgBuffer, m_bufferIndex, Output, OutOffset, Length);
		m_bufferIndex += Length;
	}
}

void CSG::FastAbsorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, std::array<ulong, STATE_SIZE> &State)
{
	std::array<byte, BUFFER_SIZE> msg;

	CexAssert(Input.size() - InOffset >= Length, "The Output buffer is too short!");

	if (Length != 0)
	{
		// sequential loop through blocks
		while (Length >= m_blockSize)
		{
			AbsorbBlock(Input, InOffset, m_blockSize, State);
			Permute(State);
			InOffset += m_blockSize;
			Length -= m_blockSize;
		}

		// store unaligned bytes
		if (Length != 0)
		{
			MemUtils::Copy(Input, InOffset, msg, 0, Length);
		}

		msg[Length] = m_domainCode;
		++Length;
		MemUtils::Clear(msg, Length, m_blockSize - Length);
		msg[m_blockSize - 1] |= 0x80;

		AbsorbBlock(msg, 0, m_blockSize, State);
	}
}

void CSG::Fill()
{
	if (!m_avxEnabled)
	{
		Permute(m_drbgState[0]);
		MemUtils::Copy(m_drbgState[0], 0, m_drbgBuffer, 0, m_blockSize);
	}
	else
	{
		PermuteW(m_drbgState);

		for (size_t i = 0; i < m_drbgState.size(); ++i)
		{
			MemUtils::Copy(m_drbgState[i], 0, m_drbgBuffer, i * m_blockSize, m_blockSize);
		}
	}

	m_bufferIndex = 0;
}

void CSG::Permute(std::array<ulong, STATE_SIZE> &State)
{
	if (m_shakeMode != ShakeModes::SHAKE1024)
	{
		// rng uses the unrolled timing-neutral permutation
		Digest::Keccak::PermuteR24P1600U(State);
	}
	else
	{
		Digest::Keccak::PermuteR48P1600U(State);
	}
}

void CSG::PermuteW(std::vector<std::array<ulong, STATE_SIZE>> &State)
{
	if (m_shakeMode != ShakeModes::SHAKE1024)
	{
#if defined(__AVX512__)
		std::vector<ULong512> tmpW(25);
		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Load(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i], m_drbgState[4][i], m_drbgState[5][i], m_drbgState[6][i], m_drbgState[7][i]);
		}

		Digest::Keccak::PermuteR24P8x1600H(tmpW);

		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Store(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i], m_drbgState[4][i], m_drbgState[5][i], m_drbgState[6][i], m_drbgState[7][i]);
		}

#elif defined(__AVX2__)
		std::vector<ULong256> tmpW(25);
		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Load(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i]);
		}

		Digest::Keccak::PermuteR24P4x1600H(tmpW);

		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Store(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i]);
		}
#endif
	}
	else
	{
#if defined(__AVX512__)
		std::vector<ULong512> tmpW(25);
		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Load(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i], m_drbgState[4][i], m_drbgState[5][i], m_drbgState[6][i], m_drbgState[7][i]);
		}

		Digest::Keccak::PermuteR48P8x1600H(tmpW);

		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Store(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i], m_drbgState[4][i], m_drbgState[5][i], m_drbgState[6][i], m_drbgState[7][i]);
		}

#elif defined(__AVX2__)
		std::vector<ULong256> tmpW(25);
		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Load(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i]);
		}

		Digest::Keccak::PermuteR48P4x1600H(tmpW);

		for (size_t i = 0; i < 25; ++i)
		{
			tmpW[i].Store(m_drbgState[0][i], m_drbgState[1][i], m_drbgState[2][i], m_drbgState[3][i]);
		}
#endif
	}
}

void CSG::Reset()
{
	MemUtils::Clear(m_drbgBuffer, 0, m_blockSize);

	for (size_t i = 0; i < m_drbgState.size(); ++i)
	{
		MemUtils::Clear(m_drbgState[i], 0, STATE_SIZE * sizeof(ulong));
	}

	m_bufferIndex = 0;
	m_isInitialized = false;
}

void CSG::Scope()
{
	if (m_avxEnabled)
	{
#if defined(__AVX512__)
		m_drbgState.resize(8);
		m_drbgBuffer.resize(m_blockSize * 8);
#elif defined(__AVX2__)
		m_drbgState.resize(4);
		m_drbgBuffer.resize(m_blockSize * 4);
#endif
	}

	Reset();

	m_distCodeMax = m_blockSize;
	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(32, 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(64, m_distCodeMax / 2, m_distCodeMax / 2);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize, m_distCodeMax / 2, m_distCodeMax / 2);
}

NAMESPACE_DRBGEND
