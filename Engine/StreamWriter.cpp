#include "StreamWriter.h"

NAMESPACE_IO

void StreamWriter::Destroy()
{

	if (_streamData.capacity() > 0)
		memset(_streamData.data(), 0, _streamData.capacity() * sizeof(byte));
	_streamData.clear();

	_streamPosition = 0;
}

std::vector<byte> StreamWriter::GetBytes()
{
	return _streamData;
}

MemoryStream StreamWriter::GetStream()
{
	_streamData.resize(_streamPosition);
	return MemoryStream(_streamData);
}

NAMESPACE_IOEND
