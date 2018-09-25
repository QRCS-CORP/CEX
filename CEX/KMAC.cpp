#include "KMAC.h"
#include "IntUtils.h"
#include "Keccak.h"

NAMESPACE_MAC

using Utility::IntUtils;
using Utility::MemUtils;

const std::string KMAC::CLASS_NAME("KMAC");

//~~~Constructor~~~//

KMAC::KMAC(ShakeModes ShakeModeType)
	:
	m_blockSize((ShakeModeType == ShakeModes::SHAKE128) ? 168 : (ShakeModeType == ShakeModes::SHAKE256) ? 136 : 72),
	m_distCode { 0x4B, 0x4D, 0x41, 0x43 },
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_macSize((ShakeModeType == ShakeModes::SHAKE128) ? 16 : (ShakeModeType == ShakeModes::SHAKE256) ? 32 :
		(ShakeModeType == ShakeModes::SHAKE512) ? 64 : 128),
	m_msgLength(0),
	m_shakeMode(ShakeModeType != ShakeModes::None ? ShakeModeType :
		throw CryptoMacException("KMAC:Ctor", "The SHAKE mode type can not ne none!"))
{
	Scope();
}

KMAC::~KMAC()
{
	if (!m_isDestroyed)
	{
		m_blockSize = 0;
		m_isDestroyed = true;
		m_isInitialized = false;
		m_macSize = 0;
		m_msgLength = 0;
		m_shakeMode = ShakeModes::None;

		Utility::IntUtils::ClearVector(m_distCode);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearArray(m_msgBuffer);
	}
}

//~~~Accessors~~~//

const size_t KMAC::BlockSize()
{
	return m_blockSize;
}

std::vector<byte> &KMAC::DistributionCode()
{
	return m_distCode;
}

const size_t KMAC::DistributionCodeMax()
{
	return m_blockSize;
}

const Macs KMAC::Enumeral()
{
	return Macs::KMAC;
}

const size_t KMAC::MacSize()
{
	return m_macSize;
}

const bool KMAC::IsInitialized()
{
	return m_isInitialized;
}

std::vector<SymmetricKeySize> KMAC::LegalKeySizes() const
{
	return m_legalKeySizes;
}

const std::string KMAC::Name()
{
	return  CLASS_NAME + "-" + IntUtils::ToString(m_macSize);
}

const ShakeModes KMAC::ShakeMode()
{
	return m_shakeMode;
}

//~~~Public Functions~~~//

void KMAC::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	CexAssert(m_isInitialized, "The Mac is not initialized!");

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t KMAC::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	CexAssert(m_isInitialized, "The Mac is not initialized!");
	CexAssert((Output.size() - OutOffset) >= m_macSize, "The Output buffer is too short!");

	std::vector<byte> buf(sizeof(size_t) + 1);
	size_t i;
	size_t outLen;
	size_t outBits;

	if (m_msgLength != m_msgBuffer.size())
	{
		Utility::MemUtils::Clear(m_msgBuffer, m_msgLength, m_msgBuffer.size() - m_msgLength);
	}

	outLen = Output.size() - OutOffset;
	outBits = RightEncode(buf, 0, outLen * 8);

	for (i = 0; i < outBits; i++)
	{
		m_msgBuffer[m_msgLength + i] = buf[i];
	}

	m_msgLength += outBits;
	m_msgBuffer[m_msgLength] = DOMAIN_CODE;
	m_msgBuffer[m_blockSize - 1] |= 128;

	AbsorbBlock(m_msgBuffer, 0, m_blockSize, m_kdfState);
	Squeeze(m_kdfState, Output, OutOffset, outLen);

	return outLen;
}

void KMAC::Initialize(ISymmetricKey &KeyParams)
{
	if (KeyParams.Key().size() == 0)
	{
		throw CryptoMacException("KMAC:Initialize", "Key size is too small; should be a minimum of digest output size!");
	}

	size_t keyLen = KeyParams.Key().size();

	if (m_isInitialized)
	{
		Reset();
	}

	if (KeyParams.Info().size() > 0)
	{
		m_distCode = KeyParams.Info();
	}

	Customize(KeyParams.Nonce(), m_distCode);
	LoadKey(KeyParams.Key());

	m_isInitialized = true;
}

void KMAC::Reset()
{
	MemUtils::Clear(m_kdfState, 0, STATE_SIZE * sizeof(ulong));
	MemUtils::Clear(m_msgBuffer, 0, BUFFER_SIZE);
	m_msgLength = 0;

	m_isInitialized = false;
}

void KMAC::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	Update(one, 0, 1);
}

void KMAC::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CexAssert(m_isInitialized, "The Mac is not initialized!");
	CexAssert((InOffset + Length) <= Input.size(), "The Input buffer is too short!");

	if (Length != 0)
	{
		if (m_msgLength != 0 && (m_msgLength + Length >= m_blockSize))
		{
			const size_t RMDLEN = m_blockSize - m_msgLength;
			if (RMDLEN != 0)
			{
				Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
			}

			AbsorbBlock(m_msgBuffer, 0, m_blockSize, m_kdfState);
			Permute(m_kdfState);
			m_msgLength = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

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
			Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

void KMAC::Customize(const std::vector<byte> &Customization, const std::vector<byte> &Name)
{
	CexAssert(!m_isInitialized, "the domain string must be set before initialization");
	CexAssert(Customization.size() + Name.size() <= 196, "the input buffer is too large");

	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	size_t offset;

	offset = 0;
	offset = LeftEncode(pad, 0, m_blockSize);
	offset += LeftEncode(pad, offset, Name.size() * 8);

	if (Name.size() != 0)
	{
		for (i = 0; i < Name.size(); i++)
		{
			if (offset == m_blockSize)
			{
				for (size_t i = 0; i < BUFFER_SIZE; i += 8)
				{
					m_kdfState[i / 8] = IntUtils::LeBytesTo64(pad, i);
				}

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
				for (size_t i = 0; i < BUFFER_SIZE; i += 8)
				{
					m_kdfState[i / 8] = IntUtils::LeBytesTo64(pad, i);
				}

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
		m_kdfState[i / 8] = IntUtils::LeBytesTo64(pad, i);
	}

	Permute(m_kdfState);
}

void KMAC::LoadKey(const std::vector<byte> &Key)
{
	CexAssert(!m_isInitialized, "the domain string must be set before initialization");

	std::array<byte, BUFFER_SIZE> pad;
	size_t i;
	size_t offset;

	offset = 0;
	offset = LeftEncode(pad, 0, m_blockSize);
	offset += LeftEncode(pad, offset, Key.size() * 8);

	if (Key.size() != 0)
	{
		for (i = 0; i < Key.size(); i++)
		{
			if (offset == m_blockSize)
			{
				for (size_t i = 0; i < BUFFER_SIZE; i += 8)
				{
					m_kdfState[i / 8] = IntUtils::LeBytesTo64(pad, i);
				}

				Permute(m_kdfState);
				offset = 0;
			}

			pad[offset] = Key[i];
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

void KMAC::Permute(std::array<ulong, 25> &State)
{
	if (m_shakeMode != ShakeModes::SHAKE1024)
	{
		Digest::Keccak::PermuteR24P1600U(State);
	}
	else
	{
		Digest::Keccak::PermuteR48P1600U(State);
	}
}

void KMAC::Scope()
{
	Reset();

	m_legalKeySizes.resize(2);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_macSize, 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_blockSize, 0, 0);
}

void KMAC::Squeeze(std::array<ulong, 25> &State, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	size_t i;
	
	while (Length > m_blockSize)
	{
		Permute(State);

		for (i = 0; i < m_blockSize / 8; ++i)
		{
			IntUtils::Le64ToBytes(State[i], Output, OutOffset + (i * 8));
		}

		OutOffset += m_blockSize;
		Length -= m_blockSize;
	}

	if (Length > 0)
	{
		Permute(State);

		for (i = 0; i < Length / 8; ++i)
		{
			IntUtils::Le64ToBytes(State[i], Output, OutOffset + (i * 8));
		}

		Length -= i * 8;

		if (Length > 0)
		{
			MemUtils::CopyFromValue(State[i], Output, OutOffset + (i * 8), Length);
		}
	}
}

NAMESPACE_MACEND
