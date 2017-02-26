#include "MemoryStream.h"
#include "ArrayUtils.h"

NAMESPACE_IO

//~~~Constructor~~~//

MemoryStream::MemoryStream()
	:
	m_isDestroyed(false),
	m_streamData(0),
	m_streamPosition(0)
{
}

MemoryStream::MemoryStream(size_t Length)
	:
	m_isDestroyed(false),
	m_streamData(0),
	m_streamPosition(0)
{
	m_streamData.reserve(Length);
}

MemoryStream::MemoryStream(const std::vector<byte> &Data)
	:
	m_isDestroyed(false),
	m_streamData(Data),
	m_streamPosition(0)
{
}

MemoryStream::MemoryStream(const std::vector<byte> &Data, size_t Offset, size_t Length)
	:
	m_isDestroyed(false),
	m_streamData(0),
	m_streamPosition(0)
{
	if (Length > Data.size() - Offset)
		throw CryptoProcessingException("MemoryStream:CTor", "Length is longer than the array size!");

	m_streamData.resize(Length);
	memcpy(&m_streamData[0], &Data[Offset], Length);
}

MemoryStream::~MemoryStream()
{
	Destroy();
}

//~~~Public Functions~~~//

void MemoryStream::Close()
{
	m_streamData.clear();
	m_streamPosition = 0;
}

void MemoryStream::CopyTo(IByteStream* Destination)
{
	Destination->Write(m_streamData, 0, m_streamData.size());
}

void MemoryStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_streamPosition = 0;
		Utility::ArrayUtils::ClearVector(m_streamData);
		m_isDestroyed = true;
	}
}

size_t MemoryStream::Read(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (Offset + Length > m_streamData.size() - m_streamPosition)
		Length = m_streamData.size() - m_streamPosition;

	if (Length > 0)
	{
		memcpy(&Output[Offset], &m_streamData[m_streamPosition], Length);
		m_streamPosition += Length;
	}

	return Length;
}

byte MemoryStream::ReadByte()
{
	if (m_streamData.size() - m_streamPosition < 1)
		throw CryptoProcessingException("MemoryStream:ReadByte", "The output array is too short!");

	byte data(1);
	memcpy(&data, &m_streamData[m_streamPosition], 1);
	m_streamPosition += 1;

	return data;
}

void MemoryStream::Reset()
{
	m_streamData.clear();
	m_streamData.resize(0);
	m_streamPosition = 0;
}

void MemoryStream::Seek(uint64_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		m_streamPosition = Offset;
	else if (Origin == SeekOrigin::End)
		m_streamPosition = m_streamData.size() - Offset;
	else
		m_streamPosition += Offset;
}

void MemoryStream::SetLength(uint64_t Length)
{
	m_streamData.reserve(Length);
}

void MemoryStream::Write(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	if (Offset + Length > Input.size())
		throw CryptoProcessingException("MemoryStream:Write", "The input array is too short!");

	size_t len = m_streamPosition + Length;
	if (m_streamData.capacity() - m_streamPosition < Length)
		m_streamData.reserve(len);
	if (m_streamData.size() < len)
		m_streamData.resize(len);

	memcpy(&m_streamData[m_streamPosition], &Input[Offset], Length);
	m_streamPosition += Length;
}

void MemoryStream::WriteByte(byte Value)
{
	if (m_streamData.size() - m_streamPosition < 1)
		m_streamData.resize(m_streamData.size() + 1);

	memcpy(&m_streamData[m_streamPosition], &Value, 1);
	m_streamPosition += 1;
}

NAMESPACE_IOEND
