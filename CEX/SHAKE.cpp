#include "SHAKE.h"
#include "Keccak.h"
#include "SymmetricKey.h"

NAMESPACE_KDF

using Utility::IntUtils;
using Utility::MemUtils;

const std::string SHAKE::CLASS_NAME("SHAKE");

//~~~Constructor~~~//

SHAKE::SHAKE(ShakeModes ShakeMode)
	:
	m_blockSize((ShakeMode == ShakeModes::SHAKE128) ? 168 : (ShakeMode == ShakeModes::SHAKE256) ? 136 : 72),
	m_domainCode(SHAKE_DOMAIN),
	m_hashSize((ShakeMode == ShakeModes::SHAKE128) ? 16 : (ShakeMode == ShakeModes::SHAKE256) ? 32 : 
		(ShakeMode == ShakeModes::SHAKE512) ? 64 : 128),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfState(),
	m_legalKeySizes(0),
	m_shakeMode(ShakeMode != ShakeModes::None ? ShakeMode :
		throw CryptoKdfException("SHAKE:Ctor", "The SHAKE mode type can not ne none!"))
{
	LoadState();
}

SHAKE::~SHAKE()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_blockSize = 0;
		m_hashSize = 0;
		m_isInitialized = false;
		m_shakeMode = ShakeModes::None;

		IntUtils::ClearArray(m_kdfState);
		IntUtils::ClearVector(m_legalKeySizes);
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

size_t SHAKE::MinKeySize()
{
	return m_hashSize;
}

const std::string SHAKE::Name()
{
	return CLASS_NAME + "-" + IntUtils::ToString(m_hashSize * 8);
}

//~~~Public Functions~~~//

size_t SHAKE::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());

	return Output.size();
}

size_t SHAKE::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	CexAssert(Output.size() != 0, "the output buffer too small");

	if (!m_isInitialized)
	{
		throw CryptoKdfException("SHAKE:Initialize", "The generator has been reset, or was not initialized!");
	}

	Expand(Output, OutOffset, Length);
	Reset();

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

void SHAKE::Initialize(const std::vector<byte> &Key)
{
	if (m_isInitialized)
	{
		Reset();
	}

	FastAbsorb(Key, 0, Key.size());
	m_isInitialized = true;
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	if (Salt.size() != 0)
	{
		std::vector<byte> tmp(0);
		Customize(Salt, tmp);
	}

	Initialize(Key);
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	if (Salt.size() != 0)
	{
		Customize(Salt, Info);
	}

	Initialize(Key);
}

void SHAKE::ReSeed(const std::vector<byte> &Seed)
{
	Initialize(Seed);
}

void SHAKE::Reset()
{
	MemUtils::Clear(m_kdfState, 0, m_kdfState.size() * sizeof(ulong));
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void SHAKE::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name)
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
				AbsorbBlock(pad, 0, m_blockSize, m_kdfState);
				Permute(m_kdfState);
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
				AbsorbBlock(pad, 0, m_blockSize, m_kdfState);
				Permute(m_kdfState);
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
		m_kdfState[i / 8] ^= IntUtils::LeBytesTo64(pad, i);
	}

	Permute(m_kdfState);
}

void SHAKE::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	while (Length != 0)
	{
		const size_t BLKLEN = IntUtils::Min(m_blockSize, Length);
		MemUtils::Copy(m_kdfState, 0, Output, OutOffset, BLKLEN);
		Permute(m_kdfState);
		Length -= BLKLEN;
		OutOffset += BLKLEN;
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
			AbsorbBlock(Input, InOffset, m_blockSize, m_kdfState);
			Permute(m_kdfState);
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
		AbsorbBlock(msg, 0, m_blockSize, m_kdfState);

		Permute(m_kdfState);
	}
}

void SHAKE::LoadState()
{
	// initialize state arrays
	Reset();
	// define legal key sizes (just a recomendation, only min size is enforced)
	m_legalKeySizes.resize(3);
	// minimum security is half the digest output size
	m_legalKeySizes[0] = SymmetricKeySize((m_hashSize / 2), 0, 0);
	// best perf/sec mix, the digest output size
	m_legalKeySizes[1] = SymmetricKeySize(m_hashSize, 0, 0);
	// max recommended key input; is one full block
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize, 0, 0);
}

void SHAKE::Permute(std::array<ulong, STATE_SIZE> &State)
{
	if (m_shakeMode != ShakeModes::SHAKE1024)
	{
		Digest::Keccak::PermuteR24P1600(State);
	}
	else
	{
		Digest::Keccak::PermuteR48P1600(State);
	}
}

NAMESPACE_KDFEND
