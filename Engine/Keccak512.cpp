#include "Keccak512.h"
#include "Keccak.h"
#include "IntUtils.h"

NAMESPACE_DIGEST

using CEX::Utility::IntUtils;

void Keccak512::BlockUpdate(const std::vector<byte> &Input, unsigned int InOffset, unsigned int Length)
{
	if ((InOffset + Length) > Input.size())
		throw CryptoDigestException("Keccak512:BlockUpdate", "The Input buffer is too short!");

	if (_bufferIndex != 0)
	{
		if (Length + _bufferIndex >= _blockSize)
		{
			int chunkSize = _blockSize - _bufferIndex;
			memcpy(&_buffer[_bufferIndex], &Input[InOffset], chunkSize);
			Keccak::TransformBlock(_buffer, 0, _state, _blockSize);
			Length -= chunkSize;
			InOffset += chunkSize;
			_bufferIndex = 0;
		}
	}

	while (Length >= _buffer.size())
	{
		Keccak::TransformBlock(Input, InOffset, _state, _blockSize);
		InOffset += _buffer.size();
		Length -= _buffer.size();
	}

	if (Length != 0)
	{
		memcpy(&_buffer[_bufferIndex], &Input[InOffset], Length);
		_bufferIndex += Length;
	}
}

void Keccak512::ComputeHash(const std::vector<byte> &Input, std::vector<byte> &Output)
{
	Output.resize(_digestSize);
	BlockUpdate(Input, 0, Input.size());
	DoFinal(Output, 0);
}

void Keccak512::Destroy()
{
	if (!_isDestroyed)
	{
		_isDestroyed = true;
		_bufferIndex = 0;
		_digestSize = 0;
		_blockSize = 0;

		IntUtils::ClearVector(_buffer);
		IntUtils::ClearVector(_state);
	}
}

unsigned int Keccak512::DoFinal(std::vector<byte> &Output, const unsigned int OutOffset)
{
	if (Output.size() - OutOffset < _digestSize)
		throw CryptoDigestException("Keccak512:DoFinal", "The Output buffer is too short!");

	memset(&_buffer[_bufferIndex], (byte)0, _buffer.size() - _bufferIndex);

	_buffer[_bufferIndex] = 1;
	_buffer[_blockSize - 1] |= 128;

	Keccak::TransformBlock(_buffer, 0, _state, _blockSize);

	_state[1] = ~_state[1];
	_state[2] = ~_state[2];
	_state[8] = ~_state[8];
	_state[12] = ~_state[12];
	_state[17] = ~_state[17];

	std::vector<byte> longBytes;
	Keccak::Word64sToBytes(_state, longBytes);
	memcpy(&Output[OutOffset], &longBytes[0], _digestSize);
	Initialize();

	return _digestSize;
}

void Keccak512::Reset()
{
	Initialize();
}

void Keccak512::Update(byte Input)
{
	std::vector<byte> one(1, Input);
	BlockUpdate(one, 0, 1);
}

// *** Protected Methods *** //

void Keccak512::Initialize()
{
	std::fill(_state.begin(), _state.end(), 0);
	_buffer.resize(_blockSize, 0);
	_bufferIndex = 0;

	const ulong UInt64_MaxValue = 0xFFFFFFFFFFFFFFFF;
	_state[1] = UInt64_MaxValue;
	_state[2] = UInt64_MaxValue;
	_state[8] = UInt64_MaxValue;
	_state[12] = UInt64_MaxValue;
	_state[17] = UInt64_MaxValue;
	_state[20] = UInt64_MaxValue;
}

NAMESPACE_DIGESTEND