#include "Poly1305.h"
#include "Donna128.h"
#include "IntegerTools.h"

NAMESPACE_MAC

using Numeric::Donna128;
using Utility::IntegerTools;
using Utility::MemoryTools;

const std::string Poly1305::CLASS_NAME("Poly1305");

//~~~Constructor~~~//

Poly1305::Poly1305()
	:
	m_isDestroyed(false),
	m_isInitialized(false),
	// Note: redundant key necessary for automation alignment
	m_legalKeySizes{ SymmetricKeySize(KEY_SIZE, 0, 0), SymmetricKeySize(KEY_SIZE, 0, 0) },
	m_msgBuffer(BLOCK_SIZE),
	m_msgLength(0)
{
}

Poly1305::~Poly1305()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_msgLength = 0;
		Utility::IntegerTools::Clear(m_macState);
		Utility::IntegerTools::Clear(m_legalKeySizes);
		Utility::IntegerTools::Clear(m_msgBuffer);

	}
}

//~~~Accessors~~~//

const size_t Poly1305::BlockSize()
{
	return BLOCK_SIZE;
}

const Macs Poly1305::Enumeral()
{
	return Macs::Poly1305;
}

const bool Poly1305::IsInitialized()
{
	return m_isInitialized;
}

std::vector<SymmetricKeySize> Poly1305::LegalKeySizes() const
{
	return m_legalKeySizes;
};

const std::string Poly1305::Name()
{
	return CLASS_NAME;
}
const size_t Poly1305::TagSize()
{
	return BLOCK_SIZE;
}


//~~~Public Functions~~~//

void Poly1305::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The MAC has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if (Output.size() < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Compute"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	Update(Input, 0, Input.size());
	Finalize(Output, 0);
}

size_t Poly1305::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	ulong c;
	ulong g0;
	ulong g1;
	ulong g2;
	ulong h0;
	ulong h1;
	ulong h2;

	if (m_msgLength != 0)
	{
		m_msgBuffer[m_msgLength] = 1;
		const size_t RMDLEN = m_msgBuffer.size() - m_msgLength - 1;

		if (RMDLEN > 0)
		{
			MemoryTools::Clear(m_msgBuffer, m_msgLength + 1, RMDLEN);
		}

		Process(m_msgBuffer, 0, BLOCK_SIZE, true);
	}

	h0 = m_macState[3];
	h1 = m_macState[4];
	h2 = m_macState[5];

	c = (h1 >> 44);
	h1 &= 0xFFFFFFFFFFFULL;
	h2 += c;  
	c = (h2 >> 42);
	h2 &= 0x3FFFFFFFFFFULL;
	h0 += c * 5;
	c = (h0 >> 44);
	h0 &= 0xFFFFFFFFFFFULL;
	h1 += c;
	c = (h1 >> 44);
	h1 &= 0xFFFFFFFFFFFULL;
	h2 += c;
	c = (h2 >> 42);
	h2 &= 0x3FFFFFFFFFFULL;
	h0 += c * 5;
	c = (h0 >> 44);
	h0 &= 0xFFFFFFFFFFFULL;
	h1 += c;
	// compute h + -p
	g0 = h0 + 5;
	c = (g0 >> 44);
	g0 &= 0xFFFFFFFFFFFULL;
	g1 = h1 + c;
	c = (g1 >> 44);
	g1 &= 0xFFFFFFFFFFFULL;
	g2 = h2 + (c - (static_cast<ulong>(1) << 42));
	// select h if h < p, or h + -p if h >= p
	c = (g2 >> ((sizeof(ulong) * 8) - 1)) - 1;
	g0 &= c;
	g1 &= c;
	g2 &= c;
	c = ~c;
	h0 = (h0 & c) | g0;
	h1 = (h1 & c) | g1;
	h2 = (h2 & c) | g2;

	// h = h + pad
	const ulong T0 = m_macState[6];
	const ulong T1 = m_macState[7];
	h0 += (T0 & 0xFFFFFFFFFFFULL);
	c = (h0 >> 44);
	h0 &= 0xFFFFFFFFFFFULL;
	h1 += (((T0 >> 44) | (T1 << 20)) & 0xFFFFFFFFFFFULL) + c;
	c = (h1 >> 44);
	h1 &= 0xFFFFFFFFFFF;
	h2 += (((T1 >> 24)) & 0x3FFFFFFFFFFULL) + c;
	h2 &= 0x3FFFFFFFFFFULL;
	// mac = h % 2^128
	h0 = ((h0) | (h1 << 44));
	h1 = ((h1 >> 20) | (h2 << 24));

	IntegerTools::Le64ToBytes(h0, Output, OutOffset);
	IntegerTools::Le64ToBytes(h1, Output, OutOffset + sizeof(ulong));

	Reset();

	return BLOCK_SIZE;
}

void Poly1305::Initialize(ISymmetricKey &KeyParams)
{
	if (!SymmetricKeySize::Contains(m_legalKeySizes, KeyParams.Key().size(), KeyParams.Nonce().size(), 0))
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Key size is invalid; must be a legal key size!"), ErrorCodes::InvalidKey);
	}

	if (m_isInitialized)
	{
		Reset();
	}

	const ulong T0 = IntegerTools::LeBytesTo64(KeyParams.Key(), 0);
	const ulong T1 = IntegerTools::LeBytesTo64(KeyParams.Key(), 1 * sizeof(ulong));

	m_macState[0] = T0 & 0xFFC0FFFFFFFULL;
	m_macState[1] = ((T0 >> 44) | (T1 << 20)) & 0xFFFFFC0FFFFULL;
	m_macState[2] = ((T1 >> 24)) & 0x00FFFFFFC0FULL;
	// h = 0
	m_macState[3] = 0;
	m_macState[4] = 0;
	m_macState[5] = 0;
	// store pad
	m_macState[6] = IntegerTools::LeBytesTo64(KeyParams.Key(), 2 * sizeof(ulong));
	m_macState[7] = IntegerTools::LeBytesTo64(KeyParams.Key(), 3 * sizeof(ulong));

	m_isInitialized = true;
}

void Poly1305::Reset()
{
	Utility::MemoryTools::Clear(m_macState, 0, m_macState.size());
	Utility::MemoryTools::Clear(m_msgBuffer, 0, m_msgBuffer.size());
	m_msgLength = 0;
	m_isInitialized = false;
}

void Poly1305::Update(byte Input)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::IllegalOperation);
	}

	if (m_msgLength == m_msgBuffer.size())
	{
		Process(m_msgBuffer, 0, BLOCK_SIZE, false);
		m_msgLength = 0;
	}

	++m_msgLength;
	m_msgBuffer[m_msgLength] = Input;
}

void Poly1305::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (!m_isInitialized)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The MAC has not been initialized!"), ErrorCodes::IllegalOperation);
	}
	if ((Input.size() - InOffset) < Length)
	{
		throw CryptoMacException(Name(), std::string("Update"), std::string("The Intput buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (Length != 0)
	{
		if (m_msgLength != 0 && (m_msgLength + Length >= BLOCK_SIZE))
		{
			const size_t RMDLEN = BLOCK_SIZE - m_msgLength;
			if (RMDLEN != 0)
			{
				Utility::MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, RMDLEN);
			}

			Process(m_msgBuffer, 0, BLOCK_SIZE, false);
			m_msgLength = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		const size_t ALNLEN = (Length / BLOCK_SIZE) * BLOCK_SIZE;
		Process(Input, InOffset, ALNLEN, false);
		Length -= ALNLEN;
		InOffset += ALNLEN;

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, m_msgBuffer, m_msgLength, Length);
			m_msgLength += Length;
		}
	}
}

//~~~Private Functions~~~//

void Poly1305::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length, bool IsFinal)
{
#if !defined(CEX_NATIVE_UINT128)
	typedef Numeric::Donna128 uint128_t;
#endif

	const ulong HIBIT = IsFinal ? 0 : (static_cast<ulong>(1) << 40);
	const ulong R0 = m_macState[0];
	const ulong R1 = m_macState[1];
	const ulong R2 = m_macState[2];
	const ulong S1 = R1 * (5 << 2);
	const ulong S2 = R2 * (5 << 2);

	uint128_t d0;
	uint128_t d1;
	uint128_t d2;
	size_t blkCtr;
	ulong c;
	ulong h0;
	ulong h1;
	ulong h2;

	blkCtr = Length / BLOCK_SIZE;
	h0 = m_macState[3];
	h1 = m_macState[4];
	h2 = m_macState[5];

	while (blkCtr != 0)
	{
		// h += m[i]
		const ulong T0 = IntegerTools::LeBytesTo64(Input, InOffset);
		const ulong T1 = IntegerTools::LeBytesTo64(Input, InOffset + sizeof(ulong));
		h0 += T0 & 0xFFFFFFFFFFFULL;
		h1 += ((T0 >> 44) | (T1 << 20)) & 0xFFFFFFFFFFFULL;
		h2 += (((T1 >> 24)) & 0x3FFFFFFFFFFULL) | HIBIT;
		// h *= r
		d0 = (uint128_t(h0) * R0) + (uint128_t(h1) * S2) + (uint128_t(h2) * S1);
		d1 = (uint128_t(h0) * R1) + (uint128_t(h1) * R0) + (uint128_t(h2) * S2);
		d2 = (uint128_t(h0) * R2) + (uint128_t(h1) * R1) + (uint128_t(h2) * R0);
		// partial h %= p
		c = Donna128::CarryShift(d0, 44);
		h0 = d0 & 0xFFFFFFFFFFFULL;
		d1 += c;
		c = Donna128::CarryShift(d1, 44);
		h1 = d1 & 0xFFFFFFFFFFFULL;
		d2 += c;
		c = Donna128::CarryShift(d2, 42);
		h2 = d2 & 0x3FFFFFFFFFFULL;
		h0 += c * 5;
		c = Donna128::CarryShift(h0, 44);
		h0 = h0 & 0xFFFFFFFFFFFULL;
		h1 += c;

		InOffset += BLOCK_SIZE;
		--blkCtr;
	}

	m_macState[3] = h0;
	m_macState[4] = h1;
	m_macState[5] = h2;
}

NAMESPACE_MACEND
