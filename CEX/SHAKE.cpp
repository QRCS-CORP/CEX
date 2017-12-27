#include "SHAKE.h"
#include "Keccak.h"
#include "IntUtils.h"
#include "MemUtils.h"
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
	m_hashSize((ShakeMode == ShakeModes::SHAKE128) ? 16 : (ShakeMode == ShakeModes::SHAKE256) ? 32 : (ShakeMode == ShakeModes::SHAKE512) ? 64 : 128),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_kdfState(),
	m_legalKeySizes(0),
	m_msgLength(0),
	m_shakeType(ShakeMode != ShakeModes::None ? ShakeMode :
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
		m_domainCode = 0;
		m_hashSize = 0;
		m_isInitialized = false;
		m_msgLength = 0;
		m_shakeType = ShakeModes::None;

		IntUtils::ClearArray(m_kdfState);
		IntUtils::ClearVector(m_legalKeySizes);
		IntUtils::ClearArray(m_msgBuffer);
	}
}

//~~~Accessors~~~//

const Kdfs SHAKE::Enumeral()
{
	return Kdfs::SHAKE;
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
	return CLASS_NAME + IntUtils::ToString(m_hashSize * 8);
}

//~~~Public Functions~~~//

void SHAKE::DomainString(std::vector<byte> &Input)
{
	CexAssert(!m_isInitialized, "the domain string must be set before initialization");
	CexAssert(Input.size() <= 200, "the input buffer is too large");

	MemUtils::Copy(Input, 0, m_kdfState, 0, Input.size());
	Permute(m_kdfState);
}

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
		throw CryptoKdfException("SHAKE:Initialize", "Key value is too small, must be at least 16 bytes in length!");
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
	if (Key.size() < m_legalKeySizes[0].KeySize())
	{
		throw CryptoKdfException("SHAKE:Initialize", "Invalid key size! Key must be at least LegalKeySizes[0].Key() size in length.");
	}

	if (m_isInitialized)
	{
		Reset();
	}

	Absorb(Key, 0, Key.size());
	HashFinal(m_kdfState);
	m_isInitialized = true;
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt)
{
	std::vector<byte> tmpK(Key.size() + Salt.size());
	MemUtils::Copy(Key, 0, tmpK, 0, Key.size());
	MemUtils::Copy(Salt, 0, tmpK, Key.size(), Salt.size());
	Initialize(tmpK);
}

void SHAKE::Initialize(const std::vector<byte> &Key, const std::vector<byte> &Salt, const std::vector<byte> &Info)
{
	std::vector<byte> tmpK(Key.size() + Salt.size() + Info.size());
	MemUtils::Copy(Key, 0, tmpK, 0, Key.size());
	MemUtils::Copy(Salt, 0, tmpK, Key.size(), Salt.size());
	MemUtils::Copy(Info, 0, tmpK, Key.size() + Salt.size(), Info.size());
	Initialize(tmpK);
}

void SHAKE::ReSeed(const std::vector<byte> &Seed)
{
	Initialize(Seed);
}

void SHAKE::Reset()
{
	std::memset(&m_kdfState[0], 0, m_kdfState.size() * sizeof(ulong));
	std::memset(&m_msgBuffer[0], 0, m_msgBuffer.size());
	m_msgLength = 0;
	m_isInitialized = false;
}

//~~~Private Functions~~~//

void SHAKE::Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
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
			MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

void SHAKE::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	while (Length != 0)
	{
		const size_t BLKSZE = IntUtils::Min(m_blockSize, Length);
		MemUtils::Copy(m_kdfState, 0, Output, OutOffset, BLKSZE);
		Permute(m_kdfState);
		Length -= BLKSZE;
		OutOffset += BLKSZE;
	}
}

void SHAKE::HashFinal(std::array<ulong, 25> &State)
{
	if (m_msgLength != m_msgBuffer.size())
	{
		MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
	}

	m_msgBuffer[m_msgLength] = m_domainCode;
	m_msgBuffer[m_blockSize - 1] |= 0x80;
	AbsorbBlock(m_msgBuffer, 0, m_msgBuffer.size(), State);
	Permute(State);
}

void SHAKE::LoadState()
{
	// initialize state arrays
	Reset();
	// define legal key sizes (just a recomendation, only min size is enforced)
	m_legalKeySizes.resize(3);
	// minimum security is the digest output size
	m_legalKeySizes[0] = SymmetricKeySize(m_hashSize, 0, 0);
	// best perf/sec mix, a full block
	m_legalKeySizes[1] = SymmetricKeySize(m_blockSize, 0, 0);
	// max key input; add two blocks
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize * 2, 0, 0);
}

void SHAKE::Permute(std::array<ulong, 25> &State)
{
	m_kdfState[1] ^= 0xFFFFFFFFFFFFFFFFULL;
	m_kdfState[2] ^= 0xFFFFFFFFFFFFFFFFULL;
	m_kdfState[8] ^= 0xFFFFFFFFFFFFFFFFULL;
	m_kdfState[12] ^= 0xFFFFFFFFFFFFFFFFULL;
	m_kdfState[17] ^= 0xFFFFFFFFFFFFFFFFULL;
	m_kdfState[20] ^= 0xFFFFFFFFFFFFFFFFULL;

	if (m_shakeType != ShakeModes::SHAKE1024)
	{
		Digest::Keccak::Permute24(State);
	}
	else
	{
		Digest::Keccak::Permute48(State);
	}

	State[1] = ~State[1];
	State[2] = ~State[2];
	State[8] = ~State[8];
	State[12] = ~State[12];
	State[17] = ~State[17];
	State[20] = ~State[20];
}

NAMESPACE_KDFEND