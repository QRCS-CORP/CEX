#include "MemoryStream.h"
#include "IntUtils.h"
#include "MemUtils.h"

NAMESPACE_IO

const std::string MemoryStream::CLASS_NAME("MemoryStream");

//~~~Properties~~~//

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

const std::string &MemoryStream::Name()
{
	return CLASS_NAME;
}

const ulong MemoryStream::Length()
{
	return static_cast<ulong>(m_streamData.size()); 
}

const ulong MemoryStream::Position() 
{ 
	return m_streamPosition;
}

std::vector<byte> &MemoryStream::ToArray() 
{ 
	return m_streamData;
}

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
	CEXASSERT(Length <= Data.size() - Offset, "Length exceeds input capacity");
	m_streamData.resize(Length);
	Utility::MemUtils::Copy<byte>(Data, Offset, m_streamData, 0, Length);
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
		Utility::IntUtils::ClearVector(m_streamData);
		m_isDestroyed = true;
	}
}

size_t MemoryStream::Read(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	if (Offset + Length > m_streamData.size() - m_streamPosition)
		Length = m_streamData.size() - m_streamPosition;

	if (Length > 0)
	{
		Utility::MemUtils::Copy<byte>(m_streamData, m_streamPosition, Output, Offset, Length);
		m_streamPosition += Length;
	}

	return Length;
}

byte MemoryStream::ReadByte()
{
	CEXASSERT(m_streamData.size() - m_streamPosition >= 1, "Stream length exceeded");
	byte data = 0;
	Utility::MemUtils::Copy<byte, byte>(m_streamData, m_streamPosition, data, 1);
	m_streamPosition += 1;

	return data;
}

void MemoryStream::Reset()
{
	Utility::MemUtils::Clear<byte>(m_streamData, 0, m_streamData.size());
	m_streamData.resize(0);
	m_streamPosition = 0;
}

void MemoryStream::Seek(ulong Offset, SeekOrigin Origin)
{
	if (Origin == SeekOrigin::Begin)
		m_streamPosition = Offset;
	else if (Origin == SeekOrigin::End)
		m_streamPosition = m_streamData.size() - Offset;
	else
		m_streamPosition += Offset;
}

void MemoryStream::SetLength(ulong Length)
{
	m_streamData.reserve(Length);
}

void MemoryStream::Write(const std::vector<byte> &Input, size_t Offset, size_t Length)
{
	CEXASSERT(Offset + Length <= Input.size(), "Input stream length exceeded");

	size_t len = m_streamPosition + Length;
	if (m_streamData.capacity() - m_streamPosition < Length)
		m_streamData.reserve(len);
	if (m_streamData.size() < len)
		m_streamData.resize(len);

	Utility::MemUtils::Copy<byte>(Input, Offset, m_streamData, m_streamPosition, Length);
	m_streamPosition += Length;
}

void MemoryStream::WriteByte(byte Value)
{
	if (m_streamData.size() - m_streamPosition < 1)
		m_streamData.resize(m_streamData.size() + 1);

	Utility::MemUtils::Copy<byte, byte>(Value, m_streamData, m_streamPosition, 1);
	m_streamPosition += 1;
}

NAMESPACE_IOEND
