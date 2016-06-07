#include "Common.h"
#include "DigestStream.h"

NAMESPACE_PROCESSING

std::vector<byte> DigestStream::ComputeHash(CEX::IO::IByteStream* InStream)
{
	if (InStream->Length() - InStream->Position() < 1)
		throw CEX::Exception::CryptoProcessingException("DigestStream:ComputeHash", "The Input stream is too short!");

	m_inStream = InStream;
	size_t dataLen = m_inStream->Length() - m_inStream->Position();
	CalculateInterval(dataLen);
	m_digestEngine->Reset();

	return Compute(dataLen);
}

std::vector<byte> DigestStream::ComputeHash(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Length - InOffset < 1 || Length - InOffset > Input.size())
		throw CEX::Exception::CryptoProcessingException("DigestStream:ComputeHash", "The Input stream is too short!");

	size_t dataLen = Length - InOffset;
	CalculateInterval(dataLen);
	m_digestEngine->Reset();

	return Compute(Input, InOffset, Length);
}

/*** Protected Methods ***/

void DigestStream::CalculateInterval(size_t Length)
{
	size_t interval = Length / 100;

	if (interval < m_blockSize)
		m_progressInterval = m_blockSize;
	else
		m_progressInterval = (interval - (interval % m_blockSize));

	if (m_progressInterval == 0)
		m_progressInterval = m_blockSize;
}

void DigestStream::CalculateProgress(size_t Length, bool Completed)
{
	if (Completed || Length % m_progressInterval == 0)
	{
		double progress = 100.0 * ((double)m_progressInterval / Length);
		ProgressPercent((int)progress);
	}
}

std::vector<byte> DigestStream::Compute(size_t Length)
{
	size_t bytesTotal = 0;
	size_t bytesRead = 0;
	std::vector<byte> buffer(m_blockSize);
	size_t maxBlocks = Length / m_blockSize;

	for (size_t i = 0; i < maxBlocks; i++)
	{
		bytesRead = m_inStream->Read(buffer, 0, m_blockSize);
		m_digestEngine->BlockUpdate(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal < Length)
	{
		buffer.resize(Length - bytesTotal);
		bytesRead = m_inStream->Read(buffer, 0, buffer.size());
		m_digestEngine->BlockUpdate(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->DoFinal(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

std::vector<byte> DigestStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	const size_t alnBlocks = (Length / m_blockSize) * m_blockSize;
	size_t bytesTotal = 0;

	while (bytesTotal != alnBlocks)
	{
		m_digestEngine->BlockUpdate(Input, InOffset, m_blockSize);
		InOffset += m_blockSize;
		bytesTotal += m_blockSize;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal != Length)
	{
		size_t diff = Length - bytesTotal;
		m_digestEngine->BlockUpdate(Input, InOffset, diff);
		bytesTotal += diff;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->DoFinal(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

void DigestStream::Destroy()
{
	m_blockSize = 0;
	m_destroyEngine = false;
	m_progressInterval = 0;

	if (m_destroyEngine)
		delete m_digestEngine;

	m_isDestroyed = true;
}

NAMESPACE_PROCESSINGEND
