#include "StreamReader.h"

NAMESPACE_IO

//~~~Constructor~~~//

StreamReader::StreamReader(const MemoryStream &DataStream)
	:
	m_streamData(DataStream)
{
}

StreamReader::~StreamReader()
{
}

//~~~Accessors~~~//

const size_t StreamReader::Length() 
{ 
	return m_streamData.Length(); 
}

const size_t StreamReader::Position() 
{ 
	return m_streamData.Position(); 
}

//~~~Public Functions~~~//

uint8_t StreamReader::ReadByte()
{
	CEXASSERT(m_streamData.Position() + sizeof(uint8_t) <= m_streamData.Length(), "Exceeds stream length");

	std::vector<uint8_t> data(1);
	m_streamData.Read(data, 0, 1);
	return data[0];
}

std::vector<uint8_t> StreamReader::ReadBytes(size_t Length)
{
	CEXASSERT(m_streamData.Position() + Length <= m_streamData.Length(), "Exceeds stream length");

	std::vector<uint8_t> data(Length);
	m_streamData.Read(data, 0, Length);
	return data;
}

NAMESPACE_IOEND
