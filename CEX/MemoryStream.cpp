#include "MemoryStream.h"
#include "IntUtils.h"

NAMESPACE_IO

void MemoryStream::Close()
{
#if defined(ENABLE_CPPEXCEPTIONS)
	throw CryptoProcessingException("MemoryStream:Flush", "Not implemented in MemoryStream!");
#endif
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
		CEX::Utility::IntUtils::ClearVector(m_streamData);
		m_isDestroyed = true;
	}
}

void MemoryStream::Flush()
{
#if defined(ENABLE_CPPEXCEPTIONS)
	throw CryptoProcessingException("MemoryStream:Flush", "Not implemented in MemoryStream!");
#endif
}

size_t MemoryStream::Read(std::vector<byte> &Buffer, size_t Offset, size_t Count)
{
	if (Offset + Count > m_streamData.size() - m_streamPosition)
		Count = m_streamData.size() - m_streamPosition;

	if (Count > 0)
	{
		memcpy(&Buffer[Offset], &m_streamData[m_streamPosition], Count);
		m_streamPosition += Count;
	}

	return Count;
}

byte MemoryStream::ReadByte()
{
#if defined(ENABLE_CPPEXCEPTIONS)
	if (m_streamData.size() - m_streamPosition < 1)
		throw CryptoProcessingException("MemoryStream:ReadByte", "The output array is too short!");
#endif

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

void MemoryStream::Seek(size_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		m_streamPosition = Offset;
	else if (Origin == SeekOrigin::End)
		m_streamPosition = m_streamData.size() - Offset;
	else
		m_streamPosition += Offset;
}

void MemoryStream::SetLength(size_t Length)
{
	m_streamData.reserve(Length);
}

void MemoryStream::Write(const std::vector<byte> &Buffer, size_t Offset, size_t Count)
{
#if defined(ENABLE_CPPEXCEPTIONS)
	if (Offset + Count > Buffer.size())
		throw CryptoProcessingException("MemoryStream:Write", "The output array is too short!");
#endif

	size_t len = m_streamPosition + Count;
	if (m_streamData.capacity() - m_streamPosition < Count)
		m_streamData.reserve(len);
	if (m_streamData.size() < len)
		m_streamData.resize(len);

	memcpy(&m_streamData[m_streamPosition], &Buffer[Offset], Count);
	m_streamPosition += Count;
}

void MemoryStream::WriteByte(byte Data)
{
	if (m_streamData.size() - m_streamPosition < 1)
		m_streamData.resize(m_streamData.size() + 1);

	memcpy(&m_streamData[m_streamPosition], &Data, 1);
	m_streamPosition += 1;
}

NAMESPACE_IOEND
