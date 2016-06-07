#include "StreamWriter.h"

NAMESPACE_IO

void StreamWriter::Destroy()
{
	if (m_streamData.capacity() > 0)
		memset(m_streamData.data(), 0, m_streamData.capacity() * sizeof(byte));
	m_streamData.clear();

	m_streamPosition = 0;
}

std::vector<byte>& StreamWriter::GetBytes()
{
	return m_streamData;
}

MemoryStream* StreamWriter::GetStream()
{
	m_streamData.resize(m_streamPosition);
	return new MemoryStream(m_streamData);
}

void StreamWriter::Write(byte Value)
{
	size_t sze = sizeof(byte);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

void StreamWriter::Write(short Value)
{
	size_t sze = sizeof(short);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

void StreamWriter::Write(ushort Value)
{
	size_t sze = sizeof(ushort);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

void StreamWriter::Write(int Value)
{
	size_t sze = sizeof(int);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

void StreamWriter::Write(uint Value)
{
	size_t sze = sizeof(uint);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

void StreamWriter::Write(long Value)
{
	size_t sze = sizeof(long);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

void StreamWriter::Write(ulong Value)
{
	size_t sze = sizeof(ulong);
	if (m_streamPosition + sze > m_streamData.size())
		m_streamData.resize(m_streamPosition + sze);

	memcpy(&m_streamData[m_streamPosition], &Value, sze);
	m_streamPosition += sze;
}

NAMESPACE_IOEND
