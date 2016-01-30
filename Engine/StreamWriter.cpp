#include "StreamWriter.h"

NAMESPACE_IO

void StreamWriter::Destroy()
{
	if (_streamData.capacity() > 0)
		memset(_streamData.data(), 0, _streamData.capacity() * sizeof(byte));
	_streamData.clear();

	_streamPosition = 0;
}

std::vector<byte>& StreamWriter::GetBytes()
{
	return _streamData;
}

MemoryStream* StreamWriter::GetStream()
{
	_streamData.resize(_streamPosition);
	return new MemoryStream(_streamData);
}

void StreamWriter::Write(byte Data)
{
	unsigned int sze = sizeof(byte);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(short Data)
{
	unsigned int sze = sizeof(short);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(ushort Data)
{
	unsigned int sze = sizeof(ushort);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(int Data)
{
	unsigned int sze = sizeof(int);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(uint Data)
{
	unsigned int sze = sizeof(uint);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(long Data)
{
	unsigned int sze = sizeof(long);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(ulong Data)
{
	unsigned int sze = sizeof(ulong);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Data, sze);
	_streamPosition += sze;
}

NAMESPACE_IOEND
