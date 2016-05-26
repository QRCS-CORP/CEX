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

void StreamWriter::Write(byte Value)
{
	size_t sze = sizeof(byte);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(short Value)
{
	size_t sze = sizeof(short);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(ushort Value)
{
	size_t sze = sizeof(ushort);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(int Value)
{
	size_t sze = sizeof(int);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(uint Value)
{
	size_t sze = sizeof(uint);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(long Value)
{
	size_t sze = sizeof(long);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

void StreamWriter::Write(ulong Value)
{
	size_t sze = sizeof(ulong);
	if (_streamPosition + sze > _streamData.size())
		_streamData.resize(_streamPosition + sze);

	memcpy(&_streamData[_streamPosition], &Value, sze);
	_streamPosition += sze;
}

NAMESPACE_IOEND
