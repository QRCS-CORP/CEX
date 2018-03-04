#include "KMAC.h"
#include "IntUtils.h"
#include "Keccak.h"

NAMESPACE_MAC

using Utility::IntUtils;
using Utility::MemUtils;

const std::string KMAC::CLASS_NAME("KMAC");

//~~~Constructor~~~//

KMAC::KMAC(ShakeModes ShakeMode)
	:
	m_blockSize((ShakeMode == ShakeModes::SHAKE128) ? 168 : (ShakeMode == ShakeModes::SHAKE256) ? 136 : 72),
	m_distributionCode { 0x4B, 0x4D, 0x41, 0x43 },
	m_isDestroyed(false),
	m_isInitialized(false),
	m_legalKeySizes(0),
	m_macSize((m_shakeMode == ShakeModes::SHAKE128) ? 16 : (m_shakeMode == ShakeModes::SHAKE256) ? 32 : (m_shakeMode == ShakeModes::SHAKE512) ? 64 : 128),
	m_msgBuffer(m_blockSize),
	m_msgLength(0),
	m_shakeMode(ShakeMode)
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

		Utility::IntUtils::ClearVector(m_distributionCode);
		Utility::IntUtils::ClearVector(m_legalKeySizes);
		Utility::IntUtils::ClearVector(m_msgBuffer);
	}
}

//~~~Accessors~~~//

const size_t KMAC::BlockSize()
{
	return m_blockSize;
}

std::vector<byte> &KMAC::DistributionCode()
{
	return m_distributionCode;
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
	uint outBits;

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
		m_distributionCode = KeyParams.Info();
	}

	LoadCustom(KeyParams.Nonce(), m_distributionCode);
	LoadKey(KeyParams.Key());

	m_isInitialized = true;
}

void KMAC::Reset()
{
	Utility::MemUtils::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	Utility::MemUtils::Clear(m_kdfState, 0, m_kdfState.size());
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
			const size_t RMDSZE = m_blockSize - m_msgLength;
			if (RMDSZE != 0)
			{
				Utility::MemUtils::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDSZE);
			}

			AbsorbBlock(m_msgBuffer, 0, m_blockSize, m_kdfState);
			Permute(m_kdfState);
			m_msgLength = 0;
			InOffset += RMDSZE;
			Length -= RMDSZE;
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

size_t KMAC::LeftEncode(std::vector<byte> &Buffer, size_t Offset, uint32_t Value)
{
	uint32_t i;
	uint32_t n;
	uint32_t v;

	for (v = Value, n = 0; v && (n < sizeof(uint32_t)); ++n, v >>= 8);

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		Buffer[Offset + i] = (uint8_t)(Value >> (8 * (n - i)));
	}

	Buffer[Offset] = (uint8_t)n;

	return static_cast<size_t>(n + 1);
}

void KMAC::LoadCustom(const std::vector<byte> &Customization, const std::vector<byte> &Name)
{
	CexAssert(!m_isInitialized, "the domain string must be set before initialization");
	CexAssert(Customization.size() + Name.size() <= 196, "the input buffer is too large");

	std::vector<byte> pad(200);
	size_t i;
	uint32_t offset;

	offset = 0;
	offset = LeftEncode(pad, 0, m_blockSize);
	offset += LeftEncode(pad, offset, Name.size() * 8);

	if (Name.size() != 0)
	{
		for (i = 0; i < Name.size(); i++)
		{
			if (offset == m_blockSize)
			{
				for (size_t i = 0; i < 200; i += 8)
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
				for (size_t i = 0; i < 200; i += 8)
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

	for (size_t i = 0; i < 200; i += 8)
	{
		m_kdfState[i / 8] = IntUtils::LeBytesTo64(pad, i);
	}

	Permute(m_kdfState);
}

void KMAC::LoadKey(const std::vector<byte> &Key)
{
	CexAssert(!m_isInitialized, "the domain string must be set before initialization");

	std::vector<byte> pad(200);
	size_t i;
	uint32_t offset;

	offset = 0;
	offset = LeftEncode(pad, 0, m_blockSize);
	offset += LeftEncode(pad, offset, Key.size() * 8);

	if (Key.size() != 0)
	{
		for (i = 0; i < Key.size(); i++)
		{
			if (offset == m_blockSize)
			{
				for (size_t i = 0; i < 200; i += 8)
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

	for (size_t i = 0; i < 200; i += 8)
	{
		m_kdfState[i / 8] ^= IntUtils::LeBytesTo64(pad, i);
	}

	Permute(m_kdfState);
}

void KMAC::Permute(std::array<ulong, 25> &State)
{
	if (m_shakeMode != ShakeModes::SHAKE1024)
	{
		Digest::Keccak::Permute24(State);
	}
	else
	{
		Digest::Keccak::Permute48(State);
	}
}

uint32_t KMAC::RightEncode(std::vector<byte> &Buffer, size_t Offset, uint32_t Value)
{
	uint32_t i;
	uint32_t n;
	uint32_t v;

	for (v = Value, n = 0; v && (n < sizeof(size_t)); ++n, v >>= 8);

	if (n == 0)
	{
		n = 1;
	}

	for (i = 1; i <= n; ++i)
	{
		Buffer[Offset + (i - 1)] = (uint8_t)(Value >> (8 * (n - i)));
	}

	Buffer[Offset + n] = (uint8_t)n;

	return n + 1;
}

void KMAC::Scope()
{
	if (m_shakeMode == ShakeModes::SHAKE1024)
	{
		m_blockSize = 72;
		m_macSize = 128;
	}
	else if (m_shakeMode == ShakeModes::SHAKE512)
	{
		m_blockSize = 72;
		m_macSize = 64;
	}
	else if (m_shakeMode == ShakeModes::SHAKE256)
	{
		m_blockSize = 136;
		m_macSize = 32;
	}
	else
	{
		m_blockSize = 168;
		m_macSize = 16;
	}


	m_msgBuffer.resize(m_blockSize);

	m_legalKeySizes.resize(3);
	// minimum seed size
	m_legalKeySizes[0] = SymmetricKeySize(m_macSize, 0, 0);
	// recommended size
	m_legalKeySizes[1] = SymmetricKeySize(m_macSize * 2, 0, 0);
	// maximum security
	m_legalKeySizes[2] = SymmetricKeySize(m_blockSize, 0, 0);
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
