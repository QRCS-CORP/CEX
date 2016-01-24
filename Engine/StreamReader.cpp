#include "StreamReader.h"
#include "CryptoProcessingException.h"

NAMESPACE_IO

using CEX::Exception::CryptoProcessingException;

void StreamReader::Destroy()
{

	if (_streamData.capacity() > 0)
		memset(_streamData.data(), 0, _streamData.capacity() * sizeof(byte));
	_streamData.clear();

	_streamPosition = 0;
}

byte StreamReader::ReadByte()
{
	if (_streamPosition < _streamData.size())
		return _streamData[_streamPosition++];

	throw CryptoProcessingException("StreamReader:ReadByte", "The array does not contain enough data!");
}

std::vector<byte> StreamReader::ReadBytes(unsigned int Length)
{
	if (_streamPosition + Length <= _streamData.size())
	{
		std::vector<byte> data(Length);
		memcpy(&data[0], &_streamData[_streamPosition], Length);
		_streamPosition += Length;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadBytes", "The array does not contain enough data!");
	}
}

short StreamReader::ReadInt16()
{
	unsigned int sze = sizeof(short);

	if (_streamPosition + sze < _streamData.size())
	{
		short data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadInt16", "The array does not contain enough data!");
	}
}

unsigned short StreamReader::ReadUInt16()
{
	unsigned int sze = sizeof(unsigned short);

	if (_streamPosition + sze < _streamData.size())
	{
		unsigned short data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadUInt16", "The array does not contain enough data!");
	}
}

int StreamReader::ReadInt32()
{
	unsigned int sze = sizeof(int);

	if (_streamPosition + sze < _streamData.size())
	{
		int data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadInt32", "The array does not contain enough data!");
	}
}

unsigned int StreamReader::ReadUInt32()
{
	unsigned int sze = sizeof(unsigned int);

	if (_streamPosition + sze < _streamData.size())
	{
		unsigned int data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadUInt32", "The array does not contain enough data!");
	}
}

long StreamReader::ReadInt64()
{
	unsigned int sze = sizeof(long);

	if (_streamPosition + sze < _streamData.size())
	{
		long data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadInt64", "The array does not contain enough data!");
	}
}

ulong StreamReader::ReadUInt64()
{
	unsigned int sze = sizeof(ulong);

	if (_streamPosition + sze < _streamData.size())
	{
		ulong data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadUInt64", "The array does not contain enough data!");
	}
}

uint StreamReader::ReadWord32()
{
	unsigned int sze = sizeof(uint);

	if (_streamPosition + sze < _streamData.size())
	{
		uint data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadWord32", "The array does not contain enough data!");
	}
}

ulong StreamReader::ReadWord64()
{
	unsigned int sze = sizeof(ulong);

	if (_streamPosition + sze < _streamData.size())
	{
		ulong data(0);
		memcpy(&data, &_streamData[_streamPosition], sze);
		_streamPosition += sze;
		return data;
	}
	else
	{
		throw CryptoProcessingException("StreamReader:ReadWord64", "The array does not contain enough data!");
	}
}

NAMESPACE_IOEND
