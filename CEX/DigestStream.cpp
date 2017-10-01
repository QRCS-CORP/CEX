#include "DigestStream.h"

NAMESPACE_PROCESSING

//~~~Properties~~~//

bool DigestStream::IsParallel()
{
	return m_digestEngine->IsParallel();
}

size_t DigestStream::ParallelBlockSize()
{
	return m_digestEngine->ParallelBlockSize();
}

ParallelOptions &DigestStream::ParallelProfile()
{
	return m_digestEngine->ParallelProfile();
}

//~~~Constructor~~~//

DigestStream::DigestStream(Digests Digest, bool Parallel)
	:
	m_digestEngine(DigestFromName::GetInstance(Digest, Parallel)),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_progressInterval(0)
{
}

DigestStream::DigestStream(IDigest* Digest)
	:
	m_digestEngine(Digest != 0 ? Digest : throw CryptoProcessingException("DigestStream:CTor", "The Digest can not be null!")),
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isParallel(m_digestEngine->IsParallel()),
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
	CEXASSERT(InStream->Length() - InStream->Position() > 0, "the input stream is too short");
	CEXASSERT(InStream->CanRead(), "the input stream is set to write only!");

	size_t dataLen = InStream->Length() - InStream->Position();
	CalculateInterval(dataLen);
	m_digestEngine->Reset();

	return Process(InStream, dataLen);
}

std::vector<byte> DigestStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT((Input.size() - InOffset) > 0 && Length + InOffset <= Input.size(), "the input array is too short");

	CalculateInterval(Length);
	m_digestEngine->Reset();

	return Process(Input, InOffset, Length);
}

//~~~Private Functions~~~//

void DigestStream::CalculateInterval(size_t Length)
{
	size_t interval = Length / 100;

	if (interval < m_digestEngine->BlockSize())
		m_progressInterval = m_digestEngine->BlockSize();
	else
		m_progressInterval = (interval - (interval % m_digestEngine->BlockSize()));

	if (m_progressInterval == 0)
		m_progressInterval = m_digestEngine->BlockSize();
}

void DigestStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * ((double)Processed / Length);
		if (progress > 100.0)
			progress = 100.0;

		if (m_isParallel)
		{
			ProgressPercent((int)progress);
		}
		else
		{
			size_t block = Length / 100;
			if (block == 0)
				ProgressPercent((int)progress);
			else if (Processed % block == 0)
				ProgressPercent((int)progress);
		}
	}
}

void DigestStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_progressInterval = 0;

		if (m_destroyEngine)
		{
			delete m_digestEngine;
			m_destroyEngine = false;
		}
	}
}

std::vector<byte> DigestStream::Process(IByteStream* InStream, size_t Length)
{
	size_t prcLen = 0;
	size_t prcRead = 0;
	std::vector<byte> inpBuffer(0);

	if (m_isParallel)
	{
		const size_t PRLBLK = m_digestEngine->ParallelBlockSize();
		if (Length > PRLBLK)
		{
			const size_t PRCSZE = (Length / PRLBLK) * PRLBLK;
			inpBuffer.resize(PRLBLK);

			while (prcLen != PRCSZE)
			{
				prcRead = InStream->Read(inpBuffer, 0, PRLBLK);
				m_digestEngine->Update(inpBuffer, 0, prcRead);
				prcLen += prcRead;
				CalculateProgress(Length, InStream->Position());
			}
		}
	}

	const size_t BLKSZE = m_digestEngine->BlockSize();
	const size_t ALNSZE = (Length / BLKSZE) * BLKSZE;
	inpBuffer.resize(BLKSZE);

	while (prcLen != ALNSZE)
	{
		prcRead = InStream->Read(inpBuffer, 0, BLKSZE);
		m_digestEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLSZE = Length - prcLen;
		inpBuffer.resize(FNLSZE);
		prcRead = InStream->Read(inpBuffer, 0, FNLSZE);
		m_digestEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

std::vector<byte> DigestStream::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	size_t prcLen = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_digestEngine->ParallelBlockSize();
		if (Length > PRLBLK)
		{
			const size_t PRCSZE = (Length / PRLBLK) * PRLBLK;

			while (prcLen != PRCSZE)
			{
				m_digestEngine->Update(Input, InOffset, PRLBLK);
				InOffset += PRLBLK;
				prcLen += PRLBLK;
				CalculateProgress(Length, InOffset);
			}
		}
	}

	const size_t BLKSZE = m_digestEngine->BlockSize();
	const size_t ALNSZE = (Length / BLKSZE) * BLKSZE;

	while (prcLen != ALNSZE)
	{
		m_digestEngine->Update(Input, InOffset, BLKSZE);
		InOffset += BLKSZE;
		prcLen += BLKSZE;
		CalculateProgress(Length, InOffset);
	}

	// last block
	if (prcLen != Length)
	{
		const size_t FNLSZE = Length - prcLen;
		m_digestEngine->Update(Input, InOffset, FNLSZE);
		prcLen += FNLSZE;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

NAMESPACE_PROCESSINGEND
