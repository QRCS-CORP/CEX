#include "SHAKE.h"
#include "ArrayTools.h"
#include "IntegerTools.h"
#include "Keccak.h"
#include "MemoryTools.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

using Utility::ArrayTools;
using Utility::IntegerTools;
using Digest::Keccak;
using Utility::MemoryTools;

const std::string SHAKE::CLASS_NAME("SHAKE");

//~~~Constructor~~~//

SHAKE::SHAKE(ShakeModes ShakeModeType)
	:
	m_blockSize((ShakeModeType == ShakeModes::SHAKE128) ? 168 : (ShakeModeType == ShakeModes::SHAKE256) ? 136 : 72),
	m_domainCode(SHAKE_DOMAIN),
	m_hashSize((ShakeModeType == ShakeModes::SHAKE128) ? 16 : (ShakeModeType == ShakeModes::SHAKE256) ? 32 :
		(ShakeModeType == ShakeModes::SHAKE512) ? 64 : 128),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfState(),
	m_legalKeySizes(0),
	m_shakeMode(ShakeModeType != ShakeModes::None ? ShakeModeType :
		throw CryptoKdfException(CLASS_NAME, std::string("Constructor"), std::string("The SHAKE mode type can not be none!"), ErrorCodes::IllegalOperation))
{
	LoadState();
}

SHAKE::~SHAKE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_domainCode = 0x00;
		m_hashSize = 0;
		m_isInitialized = false;
		m_shakeMode = ShakeModes::None;

		IntegerTools::Clear(m_kdfState);
		IntegerTools::Clear(m_legalKeySizes);
	}
}

//~~~Accessors~~~//

const size_t SHAKE::BlockSize()
{
	return m_blockSize;
}

const size_t SHAKE::Rate()
{
	return m_blockSize;
}

const Kdfs SHAKE::Enumeral()
{
	return static_cast<Kdfs>(m_shakeMode);
}

const bool SHAKE::IsInitialized()
{
	return m_isInitialized;
}

std::vector<SymmetricKeySize> SHAKE::LegalKeySizes() const
{
	return m_legalKeySizes;
};

const size_t SHAKE::MinKeySize()
{
	return m_hashSize;
}

const std::string SHAKE::Name()
{
	return CLASS_NAME + "-" + IntegerTools::ToString(m_hashSize * 8);
}

//~~~Public Functions~~~//

size_t SHAKE::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());

	return Output.size();
}

size_t SHAKE::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Expand(Output, OutOffset, Length);

	return Length;
}

void SHAKE::Initialize(ISymmetricKey &GenParam)
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

void SHAKE::Initialize(const std::vector<byte> &Key, size_t Offset, size_t Length)
{
	CexAssert(Key.size() >= Length + Offset, "The key is too small");

	std::vector<byte> tmpK(Length);

	MemoryTools::Copy(Key, Offset, tmpK, 0, Length);
	Initialize(tmpK);
}

void SHAKE::Initialize(const std::vector<byte> &Key)
{
	if (Key.size() < MIN_KEYLEN)
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Key value is too small, must be at least 16 bytes in length!"), ErrorCodes::InvalidKey);
	}

	if (m_isInitialized)
	{
		Reset();
	}

	FastAbsorb(Key, 0, Key.size());
	m_isInitialized = true;
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Key.size() < MIN_KEYLEN)
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Key value is too small, must be at least 16 bytes in length!"), ErrorCodes::InvalidKey);
	}

	if (m_isInitialized)
	{
		Reset();
	}

	if (Salt.size() != 0)
	{
		std::vector<byte> tmp(0);
		Customize(Salt, tmp);
	}

	FastAbsorb(Key, 0, Key.size());
	m_isInitialized = true;
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Key.size() < MIN_KEYLEN)
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Key value is too small, must be at least 16 bytes in length!"), ErrorCodes::InvalidKey);
	}

	if (m_isInitialized)
	{
		Reset();
	}

	if (Salt.size() != 0)
	{
		Customize(Salt, Info);
	}

	FastAbsorb(Key, 0, Key.size());
	m_isInitialized = true;
}

void SHAKE::ReSeed(const std::vector<byte> &Seed)
{
	Initialize(Seed);
}

void SHAKE::Reset()
{
	MemoryTools::Clear(m_kdfState, 0, m_kdfState.size() * sizeof(ulong));
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void SHAKE::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name)
{
	CexAssert(Customization.size() + Name.size() <= 196, "the input buffer is too large");

	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	size_t offset;

	MemoryTools::Clear(pad, 0, pad.size());
	offset = ArrayTools::LeftEncode(pad, 0, static_cast<ulong>(m_blockSize));
	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Name.size() * 8));

	m_domainCode = CSHAKE_DOMAIN;

	if (Name.size() != 0)
	{
		for (i = 0; i < Name.size(); i++)
		{
			if (offset == m_blockSize)
			{
				Keccak::Absorb(pad, 0, m_blockSize, m_kdfState);
				Permute(m_kdfState);
				offset = 0;
			}

			pad[offset] = Name[i];
			++offset;
		}
	}

	offset += ArrayTools::LeftEncode(pad, offset, static_cast<ulong>(Customization.size() * 8));

	if (Customization.size() != 0)
	{
		for (i = 0; i < Customization.size(); i++)
		{
			if (offset == m_blockSize)
			{
				Keccak::Absorb(pad, 0, m_blockSize, m_kdfState);
				Permute(m_kdfState);
				offset = 0;
			}

			pad[offset] = Customization[i];
			++offset;
		}
	}

	MemoryTools::Clear(pad, offset, BUFFER_SIZE - offset);
	offset = (offset % sizeof(ulong) == 0) ? offset : offset + (sizeof(ulong) - (offset % sizeof(ulong)));

	for (size_t i = 0; i < offset; i += 8)
	{
		m_kdfState[i / 8] ^= IntegerTools::LeBytesTo64(pad, i);
	}

	Permute(m_kdfState);
}

void SHAKE::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (Length >= m_blockSize)
	{
		const size_t BLKCNT = Length / m_blockSize;

		if (m_shakeMode != ShakeModes::SHAKE1024)
		{
			Keccak::SqueezeR24(m_kdfState, Output, OutOffset, BLKCNT, m_blockSize);
			const size_t BLKOFF = BLKCNT * m_blockSize;
			Length -= BLKOFF;
			OutOffset += BLKOFF;
		}
		else
		{
			Keccak::SqueezeR48(m_kdfState, Output, OutOffset, BLKCNT, m_blockSize);
			const size_t BLKOFF = BLKCNT * m_blockSize;
			Length -= BLKOFF;
			OutOffset += BLKOFF;
		}
	}

	if (Length != 0)
	{
		Permute(m_kdfState);
		MemoryTools::Copy(m_kdfState, 0, Output, OutOffset, Length);
	}
}

void SHAKE::FastAbsorb(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	std::array<byte, BUFFER_SIZE> msg;

	CexAssert(Input.size() - InOffset >= Length, "The Output buffer is too short!");

	if (Length != 0)
	{
		// sequential loop through blocks
		while (Length >= m_blockSize)
		{
			Keccak::Absorb(Input, InOffset, m_blockSize, m_kdfState);
			Permute(m_kdfState);
			InOffset += m_blockSize;
			Length -= m_blockSize;
		}

		// store unaligned bytes
		if (Length != 0)
		{
			MemoryTools::Copy(Input, InOffset, msg, 0, Length);
		}

		msg[Length] = m_domainCode;
		++Length;

		MemoryTools::Clear(msg, Length, m_blockSize - Length);
		msg[m_blockSize - 1] |= 0x80;
		Keccak::Absorb(msg, 0, m_blockSize, m_kdfState);
	}
}

void SHAKE::LoadState()
{
	// initialize state arrays
	Reset();
	// define legal key sizes (just a recommendation, only min size is enforced)
	m_legalKeySizes.resize(3);
	// minimum security is half the digest output size
	m_legalKeySizes[0] = SymmetricKeySize((m_hashSize / 2), 0, 0);
	// best perf/sec mix, the digest output size
	m_legalKeySizes[1] = SymmetricKeySize(m_hashSize, 0, 0);
	// max recommended key input; is two times the digest output size
	m_legalKeySizes[2] = SymmetricKeySize(m_hashSize * 2, 0, 0);
}

void SHAKE::Permute(std::array<ulong, STATE_SIZE> &State)
{
	if (m_shakeMode != ShakeModes::SHAKE1024)
	{
#if defined(CEX_DIGEST_COMPACT)
		// memory conservative compact form
		Keccak::PermuteR24P1600U(State);
#else
		// unrolled timing-neutral form
		Keccak::PermuteR24P1600U(State);
#endif
	}
	else
	{
#if defined(CEX_DIGEST_COMPACT)
		Keccak::PermuteR48P1600U(State);
#else
		Keccak::PermuteR48P1600U(State);
#endif
	}
}

NAMESPACE_KDFEND
