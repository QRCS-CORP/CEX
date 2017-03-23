#include "DigestStream.h"

NAMESPACE_PROCESSING

//~~~Constructor~~~//

DigestStream::DigestStream(Digests Digest)
	:
	m_digestEngine(DigestFromName::GetInstance(Digest)),
	m_blockSize(m_digestEngine->BlockSize()),
	m_destroyEngine(true),
	m_inStream(0),
	m_isDestroyed(false),
	m_progressInterval(0)
{
}

DigestStream::DigestStream(IDigest* Digest)
	:
	m_digestEngine(Digest != 0 ? Digest : throw CryptoProcessingException("DigestStream:CTor", "The Digest can not be null!")),
	m_blockSize(m_digestEngine->BlockSize()),
	m_destroyEngine(false),
	m_inStream(0),
	m_isDestroyed(false),
	m_progressInterval(0)
{
}

DigestStream::~DigestStream()
{
	Destroy();
}

//~~~Public Functions~~~//

std::vector<byte> DigestStream::Compute(IByteStream* InStream)
{
	if (InStream->Length() - InStream->Position() < 1)
		throw CryptoProcessingException("DigestStream:Compute", "The Input stream is too short!");

	m_inStream = InStream;
	size_t dataLen = m_inStream->Length() - m_inStream->Position();
	CalculateInterval(dataLen);
	m_digestEngine->Reset();

	return Process(dataLen);
}

std::vector<byte> DigestStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Length - InOffset < 1 || Length - InOffset > Input.size())
		throw CryptoProcessingException("DigestStream:Compute", "The Input stream is too short!");

	size_t dataLen = Length - InOffset;
	CalculateInterval(dataLen);
	m_digestEngine->Reset();

	return Process(Input, InOffset, Length);
}

//~~~Private Functions~~~//

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

std::vector<byte> DigestStream::Process(size_t Length)
{
	size_t bytesTotal = 0;
	size_t bytesRead = 0;
	std::vector<byte> buffer(m_blockSize);
	size_t maxBlocks = Length / m_blockSize;

	for (size_t i = 0; i < maxBlocks; i++)
	{
		bytesRead = m_inStream->Read(buffer, 0, m_blockSize);
		m_digestEngine->Update(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal < Length)
	{
		buffer.resize(Length - bytesTotal);
		bytesRead = m_inStream->Read(buffer, 0, buffer.size());
		m_digestEngine->Update(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

std::vector<byte> DigestStream::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	const size_t alnBlocks = (Length / m_blockSize) * m_blockSize;
	size_t bytesTotal = 0;

	while (bytesTotal != alnBlocks)
	{
		m_digestEngine->Update(Input, InOffset, m_blockSize);
		InOffset += m_blockSize;
		bytesTotal += m_blockSize;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal != Length)
	{
		size_t diff = Length - bytesTotal;
		m_digestEngine->Update(Input, InOffset, diff);
		bytesTotal += diff;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

void DigestStream::Destroy()
{
	m_isDestroyed = true;
	m_blockSize = 0;
	m_progressInterval = 0;

	if (m_destroyEngine)
	{
		delete m_digestEngine;
		m_destroyEngine = false;
	}
}

NAMESPACE_PROCESSINGEND
