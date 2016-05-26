#include "Common.h"
#include "MacStream.h"
#include "MacFromDescription.h"

NAMESPACE_PROCESSING

std::vector<byte> MacStream::ComputeMac(CEX::IO::IByteStream* InStream)
{
	if (InStream->Length() - InStream->Position() < 1)
		throw CEX::Exception::CryptoProcessingException("MacStream:ComputeHash", "The Input stream is too short!");

	m_inStream = InStream;
	size_t dataLen = m_inStream->Length() - m_inStream->Position();
	CalculateInterval(dataLen);
	m_macEngine->Reset();

	return Compute(dataLen);
}

std::vector<byte> MacStream::ComputeMac(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	if (Length - InOffset < 1 || Length - InOffset > Input.size())
		throw CEX::Exception::CryptoProcessingException("MacStream:ComputeHash", "The Input stream is too short!");

	size_t dataLen = Length - InOffset;
	CalculateInterval(dataLen);
	m_macEngine->Reset();

	return Compute(Input, InOffset, Length);
}

/*** Protected Methods ***/

void MacStream::CalculateInterval(size_t Length)
{
	size_t interval = Length / 100;

	if (interval < m_blockSize)
		m_progressInterval = m_blockSize;
	else
		m_progressInterval = (interval - (interval % m_blockSize));

	if (m_progressInterval == 0)
		m_progressInterval = m_blockSize;
}

void MacStream::CalculateProgress(size_t Length, bool Completed)
{
	if (Completed || Length % m_progressInterval == 0)
	{
		double progress = 100.0 * ((double)m_progressInterval / Length);
		ProgressPercent((int)progress);
	}
}

std::vector<byte> MacStream::Compute(size_t Length)
{
	size_t bytesTotal = 0;
	size_t bytesRead = 0;
	std::vector<byte> buffer(m_blockSize);
	size_t maxBlocks = Length / m_blockSize;

	for (size_t i = 0; i < maxBlocks; i++)
	{
		bytesRead = m_inStream->Read(buffer, 0, m_blockSize);
		m_macEngine->BlockUpdate(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal < Length)
	{
		buffer.resize(Length - bytesTotal);
		bytesRead = m_inStream->Read(buffer, 0, buffer.size());
		m_macEngine->BlockUpdate(buffer, 0, bytesRead);
		bytesTotal += bytesRead;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->MacSize());
	m_macEngine->DoFinal(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

std::vector<byte> MacStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	const size_t alnBlocks = (Length / m_blockSize) * m_blockSize;
	size_t bytesTotal = 0;

	while (bytesTotal != alnBlocks)
	{
		m_macEngine->BlockUpdate(Input, InOffset, m_blockSize);
		InOffset += m_blockSize;
		bytesTotal += m_blockSize;
		CalculateProgress(bytesTotal);
	}

	// last block
	if (bytesTotal != Length)
	{
		size_t diff = Length - bytesTotal;
		m_macEngine->BlockUpdate(Input, InOffset, diff);
		bytesTotal += diff;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->MacSize());
	m_macEngine->DoFinal(chkSum, 0);
	CalculateProgress(bytesTotal);

	return chkSum;
}

void MacStream::Destroy()
{
	m_blockSize = 0;
	m_destroyEngine = false;
	m_progressInterval = 0;

	if (m_destroyEngine)
		delete m_macEngine;

	m_isDestroyed = true;
}

void MacStream::CreateMac(CEX::Common::MacDescription &Description)
{
	m_macEngine = CEX::Helper::MacFromDescription::GetInstance(Description);
}

NAMESPACE_PROCESSINGEND
