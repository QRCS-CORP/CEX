#include "Poly1305.h"
#include "Donna128.h"
#include "IntegerTools.h"

NAMESPACE_MAC

using Numeric::Donna128;
using Tools::IntegerTools;
using Enumeration::MacConvert;
using Tools::MemoryTools;

class Poly1305::Poly1305State
{
public:

	std::array<ulong, 8> State = { 0x00 };
	std::vector<byte> Buffer;
	size_t Position;
	bool IsInitialized;

	Poly1305State(size_t BufferSize)
		:
		Buffer(BufferSize),
		Position(0),
		IsInitialized(false)
	{
	}

	~Poly1305State()
	{
		Reset();
	}

	void Reset()
	{
		Position = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(State, 0, State.size() * sizeof(ulong));
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

Poly1305::Poly1305()
	:
	MacBase(
		BLOCK_SIZE,
		Macs::Poly1305, 
		MacConvert::ToName(Macs::Poly1305), 
		std::vector<SymmetricKeySize> { 
			SymmetricKeySize(POLYKEY_SIZE, 0, 0),
			SymmetricKeySize(POLYKEY_SIZE, 0, 0),
			SymmetricKeySize(POLYKEY_SIZE, 0, 0)},
		POLYKEY_SIZE,
		MINSALT_LENGTH,
		BLOCK_SIZE),
	m_poly1305State(new Poly1305State(BLOCK_SIZE))
{
}

Poly1305::~Poly1305()
{
	if (m_poly1305State != nullptr)
	{
		m_poly1305State.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool Poly1305::IsInitialized()
{
	return m_poly1305State->IsInitialized;
}

//~~~Public Functions~~~//

void Poly1305::Compute(const std::vector<byte> &Input, std::vector<byte> &Output)
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

size_t Poly1305::Finalize(std::vector<byte> &Output, size_t OutOffset)
{
	ulong c;
	ulong g0;
	ulong g1;
	ulong g2;
	ulong h0;
	ulong h1;
	ulong h2;

	if (IsInitialized() == false)
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The MAC has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < TagSize())
	{
		throw CryptoMacException(Name(), std::string("Finalize"), std::string("The Output buffer is too short!"), ErrorCodes::InvalidSize);
	}

	if (m_poly1305State->Position != 0)
	{
		m_poly1305State->Buffer[m_poly1305State->Position] = 0x01;
		const size_t RMDLEN = m_poly1305State->Buffer.size() - m_poly1305State->Position - 1;

		if (RMDLEN > 0)
		{
			MemoryTools::Clear(m_poly1305State->Buffer, m_poly1305State->Position + 1, RMDLEN);
		}

		Absorb(m_poly1305State->Buffer, 0, BLOCK_SIZE, true, m_poly1305State);
	}

	h0 = m_poly1305State->State[3];
	h1 = m_poly1305State->State[4];
	h2 = m_poly1305State->State[5];

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
	const ulong T0 = m_poly1305State->State[6];
	const ulong T1 = m_poly1305State->State[7];
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

	return TagSize();
}

size_t Poly1305::Finalize(SecureVector<byte> &Output, size_t OutOffset)
{
	std::vector<byte> tag(TagSize());

	Finalize(tag, 0);
	SecureMove(tag, 0, Output, OutOffset, tag.size());

	return TagSize();
}

void Poly1305::Initialize(ISymmetricKey &Parameters)
{
	if (Parameters.KeySizes().KeySize() < MinimumKeySize())
	{
		throw CryptoMacException(Name(), std::string("Initialize"), std::string("Invalid key size, must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}

	const ulong T0 = IntegerTools::LeBytesTo64(Parameters.Key(), 0);
	const ulong T1 = IntegerTools::LeBytesTo64(Parameters.Key(), sizeof(ulong));

	if (IsInitialized() == true)
	{
		Reset();
	}

	m_poly1305State->State[0] = T0 & 0xFFC0FFFFFFFULL;
	m_poly1305State->State[1] = ((T0 >> 44) | (T1 << 20)) & 0xFFFFFC0FFFFULL;
	m_poly1305State->State[2] = ((T1 >> 24)) & 0x00FFFFFFC0FULL;
	// h=0
	m_poly1305State->State[3] = 0;
	m_poly1305State->State[4] = 0;
	m_poly1305State->State[5] = 0;
	// store pad
	m_poly1305State->State[6] = IntegerTools::LeBytesTo64(Parameters.Key(), 2 * sizeof(ulong));
	m_poly1305State->State[7] = IntegerTools::LeBytesTo64(Parameters.Key(), 3 * sizeof(ulong));

	m_poly1305State->IsInitialized = true;
}

void Poly1305::Reset()
{
	m_poly1305State->Reset();
	m_poly1305State->IsInitialized = false;
}

void Poly1305::Update(const std::vector<byte> &Input, size_t InOffset, size_t Length)
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
		if (m_poly1305State->Position != 0 && (m_poly1305State->Position + Length >= BLOCK_SIZE))
		{
			const size_t RMDLEN = BLOCK_SIZE - m_poly1305State->Position;
			if (RMDLEN != 0)
			{
				MemoryTools::Copy(Input, InOffset, m_poly1305State->Buffer, m_poly1305State->Position, RMDLEN);
			}

			Absorb(m_poly1305State->Buffer, 0, BLOCK_SIZE, false, m_poly1305State);
			m_poly1305State->Position = 0;
			InOffset += RMDLEN;
			Length -= RMDLEN;
		}

		const size_t ALNLEN = (Length / BLOCK_SIZE) * BLOCK_SIZE;
		Absorb(Input, InOffset, ALNLEN, false, m_poly1305State);
		Length -= ALNLEN;
		InOffset += ALNLEN;

		if (Length > 0)
		{
			MemoryTools::Copy(Input, InOffset, m_poly1305State->Buffer, m_poly1305State->Position, Length);
			m_poly1305State->Position += Length;
		}
	}
}

//~~~Private Functions~~~//

void Poly1305::Absorb(const std::vector<byte> &Input, size_t InOffset, size_t Length, bool IsFinal, std::unique_ptr<Poly1305State> &State)
{
#if !defined(CEX_NATIVE_UINT128)
	typedef Numeric::Donna128 uint128_t;
#endif

	const ulong HIBIT = IsFinal ? 0 : (static_cast<ulong>(1) << 40);
	const ulong R0 = State->State[0];
	const ulong R1 = State->State[1];
	const ulong R2 = State->State[2];
	const ulong S1 = R1 * (5 << 2);
	const ulong S2 = R2 * (5 << 2);
	uint128_t d0;
	uint128_t d1;
	uint128_t d2;
	ulong c;
	ulong h0;
	ulong h1;
	ulong h2;
	size_t bctr;

	bctr = Length / BLOCK_SIZE;
	h0 = State->State[3];
	h1 = State->State[4];
	h2 = State->State[5];

	while (bctr != 0)
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
		--bctr;
	}

	State->State[3] = h0;
	State->State[4] = h1;
	State->State[5] = h2;
}

NAMESPACE_MACEND
