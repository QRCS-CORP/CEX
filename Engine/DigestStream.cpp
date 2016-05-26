#include "Common.h"
#include "DigestStream.h"

NAMESPACE_PROCESSING

std::vector<byte> DigestStream::ComputeHash(CEX::IO::IByteStream* InStream)
{
	if (InStream->Length() - InStream->Position() < 1)
		throw CEX::Exception::CryptoProcessingException("DigestStream:ComputeHash", "The Input stream is too short!");

	_inStream = InStream;
	size_t dataLen = _inStream->Length() - _inStream->Position();
	CalculateInterval(dataLen);
	_digestEngine->Reset();

	return Compute(dataLen);
}

std::vector<byte> DigestStream::ComputeHash(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Length - InOffset < 1 || Length - InOffset > Input.size())
		throw CEX::Exception::CryptoProcessingException("DigestStream:ComputeHash", "The Input stream is too short!");

	size_t dataLen = Length - InOffset;
	CalculateInterval(dataLen);
	_digestEngine->Reset();

	return Compute(Input, InOffset, Length);
}

/*** Protected Methods ***/

void DigestStream::CalculateInterval(size_t Length)
{
	size_t interval = Length / 100;

	if (interval < _blockSize)
		_progressInterval = _blockSize;
	else
		_progressInterval = (interval - (interval % _blockSize));

	if (_progressInterval == 0)
		_progressInterval = _blockSize;
}

void DigestStream::CalculateProgress(size_t Length, bool Completed)
{
	if (Completed || Length % _progressInterval == 0)
	{
		double progress = 100.0 * ((double)_progressInterval / Length);
		ProgressPercent((int)progress);
	}
}

std::vector<byte> DigestStream::Compute(size_t Length)
{
	size_t bytesTotal = 0;
	size_t bytesRead = 0;
	std::vector<byte> buffer(_blockSize);
	size_t maxBlocks = Length / _blockSize;

	for (size_t i = 0; i < maxBlocks; i++)
	{
		bytesRead = _inStream->Read(buffer, 0, _blockSize);
		_digestEngine->BlockUpdate(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal < Length)
	{
		buffer.resize(Length - bytesTotal);
		bytesRead = _inStream->Read(buffer, 0, buffer.size());
		_digestEngine->BlockUpdate(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
	}

	// get the hash
	std::vector<byte> chkSum(_digestEngine->DigestSize());
	_digestEngine->DoFinal(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

std::vector<byte> DigestStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	const size_t alnBlocks = (Length / _blockSize) * _blockSize;
	size_t bytesTotal = 0;

	while (bytesTotal != alnBlocks)
	{
		_digestEngine->BlockUpdate(Input, InOffset, _blockSize);
		InOffset += _blockSize;
		bytesTotal += _blockSize;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal != Length)
	{
		size_t diff = Length - bytesTotal;
		_digestEngine->BlockUpdate(Input, InOffset, diff);
		bytesTotal += diff;
	}

	// get the hash
	std::vector<byte> chkSum(_digestEngine->DigestSize());
	_digestEngine->DoFinal(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

void DigestStream::Destroy()
{
	_blockSize = 0;
	_destroyEngine = false;
	_progressInterval = 0;

	if (_destroyEngine)
		delete _digestEngine;

	_isDestroyed = true;
}

NAMESPACE_PROCESSINGEND
