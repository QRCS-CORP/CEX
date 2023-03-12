#include "SecureRandom.h"
#include "BitConverter.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"
#include "PrngFromName.h"

NAMESPACE_PRNG

using IO::BitConverter;
using Tools::MemoryTools;

class SecureRandom::ScrState
{
public:

	SecureVector<uint8_t> Buffer;
	size_t Position;

	ScrState(Providers ProviderType)
		:
		Buffer(BUFFER_SIZE),
		Position(BUFFER_SIZE)
	{
	}

	~ScrState()
	{
		Reset();
	}

	void Reset()
	{
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		Position = 0;
	}
};

//~~~Constructor~~~//

SecureRandom::SecureRandom(Prngs PrngType, Providers ProviderType)
	:
	m_scrState(ProviderType != Providers::None && PrngType != Prngs::None ?
		new ScrState(ProviderType) :
		throw CryptoRandomException(std::string("SecureRandom"), std::string("Constructor"), std::string("Prng mode and Provider type can not be none!"), ErrorCodes::InvalidParam)),
	m_rngEngine(Helper::PrngFromName::GetInstance(PrngType, ProviderType))
{
}

SecureRandom::~SecureRandom()
{
	if (m_rngEngine != nullptr)
	{
		m_rngEngine.reset(nullptr);
	}

	if (m_scrState != nullptr)
	{
		m_scrState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const std::string SecureRandom::Name()
{
	return m_rngEngine->Name();
}

//~~~Public Functions~~~//

void SecureRandom::Fill(std::vector<uint16_t> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	std::vector<uint8_t> buf(Elements * sizeof(uint16_t));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

void SecureRandom::Fill(SecureVector<uint16_t> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	SecureVector<uint8_t> buf(Elements * sizeof(uint16_t));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

void SecureRandom::Fill(std::vector<uint32_t> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	std::vector<uint8_t> buf(Elements * sizeof(uint32_t));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

void SecureRandom::Fill(std::vector<uint64_t> &Output, size_t Offset, size_t Elements)
{
	if (Offset + Elements > Output.size())
	{
		throw CryptoRandomException(Name(), std::string("Fill"), std::string("The output vector is too small!"), ErrorCodes::InvalidParam);
	}

	std::vector<uint8_t> buf(Elements * sizeof(uint64_t));
	Generate(buf);
	MemoryTools::Copy(buf, 0, Output, Offset, buf.size());
}

std::vector<uint8_t> SecureRandom::Generate(size_t Length)
{
	std::vector<uint8_t> rnd(Length);
	Generate(rnd);

	return rnd;
}

void SecureRandom::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	const size_t BUFLEN = m_scrState->Buffer.size() - m_scrState->Position;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureMove(m_scrState->Buffer, m_scrState->Position, Output, Offset, BUFLEN);
			}

			while (Length >= m_scrState->Buffer.size())
			{
				m_rngEngine->Generate(m_scrState->Buffer, 0, m_scrState->Buffer.size());
				SecureMove(m_scrState->Buffer, 0, Output, Offset, m_scrState->Buffer.size());
				Length -= m_scrState->Buffer.size();
				Offset += m_scrState->Buffer.size();
			}

			m_rngEngine->Generate(m_scrState->Buffer, 0, m_scrState->Buffer.size());
			SecureMove(m_scrState->Buffer, 0, Output, Offset, Length);
			m_scrState->Position = Length;
		}
		else
		{
			SecureMove(m_scrState->Buffer, m_scrState->Position, Output, Offset, Length);
			m_scrState->Position += Length;
		}
	}
}

void SecureRandom::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	const size_t BUFLEN = m_scrState->Buffer.size() - m_scrState->Position;

	if (Length != 0)
	{
		if (Length > BUFLEN)
		{
			if (BUFLEN > 0)
			{
				SecureCopy(m_scrState->Buffer, m_scrState->Position, Output, Offset, BUFLEN);
			}

			while (Length >= m_scrState->Buffer.size())
			{
				m_rngEngine->Generate(m_scrState->Buffer, 0, m_scrState->Buffer.size());
				SecureCopy(m_scrState->Buffer, 0, Output, Offset, m_scrState->Buffer.size());
				Length -= m_scrState->Buffer.size();
				Offset += m_scrState->Buffer.size();
			}

			m_rngEngine->Generate(m_scrState->Buffer, 0, m_scrState->Buffer.size());
			SecureCopy(m_scrState->Buffer, 0, Output, Offset, Length);
			m_scrState->Position = Length;
		}
		else
		{
			SecureCopy(m_scrState->Buffer, m_scrState->Position, Output, Offset, Length);
			m_scrState->Position += Length;
		}
	}
}

void SecureRandom::Generate(std::vector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size());
}

void SecureRandom::Generate(SecureVector<uint8_t> &Output)
{
	Generate(Output, 0, Output.size());
}

char SecureRandom::NextChar()
{
	std::vector<uint8_t> smp(sizeof(char));
	Generate(smp);

	return BitConverter::ToChar(smp, 0);
}

uint8_t SecureRandom::NextUChar()
{
	std::vector<uint8_t> smp(sizeof(char));
	Generate(smp);

	return BitConverter::ToUChar(smp, 0);
}

double SecureRandom::NextDouble()
{
	std::vector<uint8_t> smp(sizeof(double));
	Generate(smp);

	return BitConverter::ToDouble(smp, 0);
}

int16_t SecureRandom::NextInt16()
{
	std::vector<uint8_t> smp(sizeof(int16_t));
	Generate(smp);

	return BitConverter::ToInt16(smp, 0);
}

int16_t SecureRandom::NextInt16(int16_t Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}

	const int16_t SMPMAX = static_cast<int16_t>(std::numeric_limits<int16_t>::max() - (std::numeric_limits<int16_t>::max() % Maximum));
	int16_t x;
	int16_t ret;

	do
	{
		x = NextInt16();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX || ret < 0);

	return ret;
}

int16_t SecureRandom::NextInt16(int16_t Maximum, int16_t Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextInt16"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

	const int16_t SMPTHR = (Maximum - Minimum + 1);
	const int16_t SMPMAX = static_cast<int16_t>(std::numeric_limits<int16_t>::max() - (std::numeric_limits<int16_t>::max() % SMPTHR));
	int16_t x;
	int16_t ret;

	do
	{
		x = NextInt16();
		ret = x % SMPTHR;
	}
	while (x >= SMPMAX || ret < 0);

	return Minimum + ret;
}

uint16_t SecureRandom::NextUInt16()
{
	std::vector<uint8_t> smp(sizeof(uint16_t));
	Generate(smp);

	return BitConverter::ToUInt16(smp, 0);
}

uint16_t SecureRandom::NextUInt16(uint16_t Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}

	const uint16_t SMPMAX = static_cast<uint16_t>(std::numeric_limits<uint16_t>::max() - (std::numeric_limits<uint16_t>::max() % Maximum));
	uint16_t x;
	uint16_t ret;

	do
	{
		x = NextUInt16();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX);

	return ret;
}

uint16_t SecureRandom::NextUInt16(uint16_t Maximum, uint16_t Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt16"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt16"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

	const uint16_t SMPTHR = (Maximum - Minimum + 1);
	const uint16_t SMPMAX = static_cast<uint16_t>(std::numeric_limits<uint16_t>::max() - (std::numeric_limits<uint16_t>::max() % SMPTHR));
	uint16_t x;
	uint16_t ret;

	do
	{
		x = NextUInt16();
		ret = x % SMPTHR;
	} 
	while (x >= SMPMAX);

	return Minimum + ret;
}

int32_t SecureRandom::NextInt32()
{
	std::vector<uint8_t> smp(sizeof(int32_t));
	Generate(smp);

	return BitConverter::ToInt32(smp, 0);
}

int32_t SecureRandom::NextInt32(int32_t Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}

	const int32_t SMPMAX = static_cast<int32_t>(std::numeric_limits<int32_t>::max() - (std::numeric_limits<int32_t>::max() % Maximum));
	int32_t x;
	int32_t ret;

	do
	{
		x = NextInt32();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX || ret < 0);

	return ret;
}

int32_t SecureRandom::NextInt32(int32_t Maximum, int32_t Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextInt32"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

	const int32_t SMPTHR = (Maximum - Minimum + 1);
	const int32_t SMPMAX = static_cast<int32_t>(std::numeric_limits<int32_t>::max() - (std::numeric_limits<int32_t>::max() % SMPTHR));
	int32_t x;
	int32_t ret;

	do
	{
		x = NextInt32();
		ret = x % SMPTHR;
	} 
	while (x >= SMPMAX || ret < 0);

	return Minimum + ret;
}

uint32_t SecureRandom::NextUInt32()
{
	std::vector<uint8_t> smp(sizeof(uint32_t));
	Generate(smp);

	return BitConverter::ToUInt32(smp, 0);
}

uint32_t SecureRandom::NextUInt32(uint32_t Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}

	const uint32_t SMPMAX = static_cast<uint32_t>(std::numeric_limits<uint32_t>::max() - (std::numeric_limits<uint32_t>::max() % Maximum));
	uint32_t x;
	uint32_t ret;

	do
	{
		x = NextUInt32();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX);

	return ret;
}

uint32_t SecureRandom::NextUInt32(uint32_t Maximum, uint32_t Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt32"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt32"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

	const uint32_t SMPTHR = (Maximum - Minimum + 1);
	const uint32_t SMPMAX = static_cast<uint32_t>(std::numeric_limits<uint32_t>::max() - (std::numeric_limits<uint32_t>::max() % SMPTHR));
	uint32_t x;
	uint32_t ret;

	do
	{
		x = NextUInt32();
		ret = x % SMPTHR;
	}
	while (x >= SMPMAX);

	return Minimum + ret;
}

int64_t SecureRandom::NextInt64()
{
	std::vector<uint8_t> smp(sizeof(int64_t));
	Generate(smp);

	return BitConverter::ToInt64(smp, 0);
}

int64_t SecureRandom::NextInt64(int64_t Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}

	const int64_t SMPMAX = static_cast<int64_t>(std::numeric_limits<int64_t>::max() - (std::numeric_limits<int64_t>::max() % Maximum));
	int64_t x;
	int64_t ret;

	do
	{
		x = NextInt64();
		ret = x % Maximum;
	} 
	while (x >= SMPMAX || ret < 0);

	return ret;
}

int64_t SecureRandom::NextInt64(int64_t Maximum, int64_t Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextInt64"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

	const int64_t SMPTHR = (Maximum - Minimum + 1);
	const int64_t SMPMAX = static_cast<int64_t>(std::numeric_limits<int64_t>::max() - (std::numeric_limits<int64_t>::max() % SMPTHR));
	int64_t x;
	int64_t ret;

	do
	{
		x = NextInt64();
		ret = x % SMPTHR;
	}
	while (x >= SMPMAX || ret < 0);

	return Minimum + ret;
}

uint64_t SecureRandom::NextUInt64()
{
	std::vector<uint8_t> smp(sizeof(uint64_t));
	Generate(smp);

	return BitConverter::ToUInt64(smp, 0);
}

uint64_t SecureRandom::NextUInt64(uint64_t Maximum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}

	const uint64_t SMPMAX = static_cast<uint64_t>(std::numeric_limits<uint64_t>::max() - (std::numeric_limits<uint64_t>::max() % Maximum));
	uint64_t x;
	uint64_t ret;

	do
	{
		x = NextUInt64();
		ret = x % Maximum;
	}
	while (x >= SMPMAX);

	return ret;
}

uint64_t SecureRandom::NextUInt64(uint64_t Maximum, uint64_t Minimum)
{
	if (Maximum < 1)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt64"), std::string("Maximum can not be zero!"), ErrorCodes::IllegalOperation);
	}
	if (Maximum < Minimum)
	{
		throw CryptoRandomException(Name(), std::string("NextUInt64"), std::string("Maximum can not be less than Minimum!"), ErrorCodes::IllegalOperation);
	}

	const uint64_t SMPTHR = (Maximum - Minimum + 1);
	const uint64_t SMPMAX = (std::numeric_limits<uint64_t>::max() - (std::numeric_limits<uint64_t>::max() % SMPTHR));
	uint64_t x;
	uint64_t ret;

	do
	{
		x = NextUInt64();
		ret = x % SMPTHR;
	} 
	while (x >= SMPMAX);

	return Minimum + ret;
}

NAMESPACE_PRNGEND
