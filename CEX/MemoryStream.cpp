#include "IntegerTools.h"
#include "MemoryStream.h"

NAMESPACE_IO

using Tools::IntegerTools;
using Tools::MemoryTools;

const std::string MemoryStream::CLASS_NAME("MemoryStream");

//~~~Constructor~~~//

MemoryStream::MemoryStream()
	:
	m_isDestroyed(false),
	m_streamData(0),
	m_streamPosition(0)
{
}

MemoryStream::MemoryStream(const MemoryStream &Stream)
	:
	m_isDestroyed(false),
	m_streamData(Stream.m_streamData),
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

MemoryStream::MemoryStream(const std::vector<uint8_t> &Data)
	:
	m_isDestroyed(false),
	m_streamData(Data),
	m_streamPosition(0)
{
}

MemoryStream::MemoryStream(const std::vector<uint8_t> &Data, size_t Offset, size_t Length)
	:
	m_isDestroyed(false),
	m_streamData(0),
	m_streamPosition(0)
{
	CEXASSERT(Length <= Data.size() - Offset, "Length exceeds input capacity");

	m_streamData.resize(Length);
	MemoryTools::Copy(Data, Offset, m_streamData, 0, Length);
}

MemoryStream::~MemoryStream()
{
	Destroy();
}

//~~~Accessors~~~//

const bool MemoryStream::CanRead()
{
	return true;
}

const bool MemoryStream::CanSeek()
{ 
	return true;
}

const bool MemoryStream::CanWrite() 
{
	return true; 
}

const StreamModes MemoryStream::Enumeral()
{ 
	return StreamModes::MemoryStream;
}

const std::string MemoryStream::Name()
{
	return CLASS_NAME;
}

const uint64_t MemoryStream::Length()
{
	return static_cast<uint64_t>(m_streamData.size()); 
}

const uint64_t MemoryStream::Position() 
{ 
	return m_streamPosition;
}

std::vector<uint8_t> &MemoryStream::ToArray() 
{ 
	return m_streamData;
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
		m_isDestroyed = true;
		m_streamPosition = 0;
		IntegerTools::Clear(m_streamData);
	}
}

size_t MemoryStream::Read(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (Offset + Length > m_streamData.size() - m_streamPosition)
	{
		Length = m_streamData.size() - m_streamPosition;
	}

	if (Length > 0)
	{
		MemoryTools::Copy(m_streamData, m_streamPosition, Output, Offset, Length);
		m_streamPosition += Length;
	}

	return Length;
}

uint8_t MemoryStream::ReadByte()
{
	CEXASSERT(m_streamData.size() - m_streamPosition >= 1, "Stream length exceeded");
	uint8_t data = 0;
	MemoryTools::CopyToValue(m_streamData, m_streamPosition, data, 1);
	m_streamPosition += 1;

	return data;
}

void MemoryStream::Reset()
{
	MemoryTools::Clear(m_streamData, 0, m_streamData.size());
	m_streamData.resize(0);
	m_streamPosition = 0;
}

void MemoryStream::Seek(uint64_t Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
	{
		m_streamPosition = Offset;
	}
	else if (Origin == SeekOrigin::End)
	{
		m_streamPosition = m_streamData.size() - Offset;
	}
	else
	{
		m_streamPosition += Offset;
	}
}

void MemoryStream::SetLength(uint64_t Length)
{
	m_streamData.reserve(Length);
}

void MemoryStream::Write(const std::vector<uint8_t> &Input, size_t Offset, size_t Length)
{
	CEXASSERT(Offset + Length <= Input.size(), "Input stream length exceeded");

	size_t ttlLen = m_streamPosition + Length;

	if (m_streamData.capacity() - m_streamPosition < Length)
	{
		m_streamData.reserve(ttlLen);
	}
	if (m_streamData.size() < ttlLen)
	{
		m_streamData.resize(ttlLen);
	}

	MemoryTools::Copy(Input, Offset, m_streamData, m_streamPosition, Length);
	m_streamPosition += Length;
}

void MemoryStream::WriteByte(uint8_t Value)
{
	if (m_streamData.size() - m_streamPosition < 1)
	{
		m_streamData.resize(m_streamData.size() + 1);
	}

	MemoryTools::CopyFromValue(Value, m_streamData, m_streamPosition, 1);
	m_streamPosition += 1;
}

NAMESPACE_IOEND
