#include "StreamWriter.h"

NAMESPACE_IO

//~~~Properties~~~//

const size_t StreamWriter::Length() 
{
	return m_streamData.size();
}

const size_t StreamWriter::Position() 
{ 
	return m_streamPosition;
}

//~~~Constructor~~~//

StreamWriter::StreamWriter(size_t Length)
	:
	m_streamData(Length),
	m_streamPosition(0)
{
}

StreamWriter::StreamWriter(const std::vector<byte> &DataArray)
	:
	m_streamData(DataArray),
	m_streamPosition(0)
{
}

StreamWriter::StreamWriter(MemoryStream &DataStream)
	:
	m_streamData(DataStream.ToArray()),
	m_streamPosition(0)
{
}

StreamWriter::~StreamWriter()
{
	Destroy();
}

//~~~Public Functions~~~//

void StreamWriter::Destroy()
{
	if (m_streamData.capacity() > 0)
		Utility::MemUtils::Clear<byte>(m_streamData, 0, m_streamData.size());

	m_streamData.clear();
	m_streamPosition = 0;
}

std::vector<byte> &StreamWriter::GetBytes()
{
	return m_streamData;
}

MemoryStream* StreamWriter::GetStream()
{
	m_streamData.resize(m_streamPosition);
	return new MemoryStream(m_streamData);
}

NAMESPACE_IOEND
