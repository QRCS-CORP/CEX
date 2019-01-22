#include "DigestStream.h"

NAMESPACE_PROCESSING

using Exception::ErrorCodes;

const std::string DigestStream::CLASS_NAME("MacStream");

//~~~Constructor~~~//

DigestStream::DigestStream(Digests DigestType, bool Parallel)
	:
	m_digestEngine(DigestType != Digests::None ? DigestFromName::GetInstance(DigestType, Parallel) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Digest type can not be none!"), ErrorCodes::IllegalOperation)),
	m_destroyEngine(true),
	m_isDestroyed(false),
	m_isParallel(Parallel),
	m_progressInterval(0)
{
}

DigestStream::DigestStream(IDigest* Digest)
	:
	m_digestEngine(Digest != nullptr ? Digest :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Digest can not be null!"), ErrorCodes::IllegalOperation)),
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

//~~~Accessors~~~//

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

//~~~Public Functions~~~//

std::vector<byte> DigestStream::Compute(IByteStream* InStream)
{
	CEXASSERT(InStream->Length() - InStream->Position() > 0, "The input stream is too short");
	CEXASSERT(InStream->CanRead(), "The input stream is set to write only!");

	size_t dataLen = InStream->Length() - InStream->Position();
	CalculateInterval(dataLen);
	m_digestEngine->Reset();

	return Process(InStream, dataLen);
}

std::vector<byte> DigestStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT((Input.size() - InOffset) > 0 && Length + InOffset <= Input.size(), "The input array is too short");

	CalculateInterval(Length);
	m_digestEngine->Reset();

	return Process(Input, InOffset, Length);
}

//~~~Private Functions~~~//

void DigestStream::CalculateInterval(size_t Length)
{
	size_t interval;

	interval = Length / 100;

	if (interval < m_digestEngine->BlockSize())
	{
		m_progressInterval = m_digestEngine->BlockSize();
	}
	else
	{
		m_progressInterval = (interval - (interval % m_digestEngine->BlockSize()));
	}

	if (m_progressInterval == 0)
	{
		m_progressInterval = m_digestEngine->BlockSize();
	}
}

void DigestStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * (static_cast<double>(Processed) / Length);
		if (progress > 100.0)
		{
			progress = 100.0;
		}

		if (m_isParallel)
		{
			ProgressPercent(static_cast<int>(progress));
		}
		else
		{
			size_t block = Length / 100;
			if (block == 0)
			{
				ProgressPercent(static_cast<int>(progress));
			}
			else if (Processed % block == 0)
			{
				ProgressPercent(static_cast<int>(progress));
			}
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
			m_destroyEngine = false;

			if (m_digestEngine != nullptr)
			{
				m_digestEngine.reset(nullptr);
			}
		}
		else
		{
			if (m_digestEngine != nullptr)
			{
				m_digestEngine.release();
			}
		}
	}
}

std::vector<byte> DigestStream::Process(IByteStream* InStream, size_t Length)
{
	const size_t BLKLEN = m_digestEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	size_t prcLen;
	size_t prcRead;
	std::vector<byte> inpBuffer(0);

	prcLen = 0;
	prcRead = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_digestEngine->ParallelBlockSize();
		if (Length > PRLBLK)
		{
			const size_t PRCLEN = (Length / PRLBLK) * PRLBLK;
			inpBuffer.resize(PRLBLK);

			while (prcLen != PRCLEN)
			{
				prcRead = InStream->Read(inpBuffer, 0, PRLBLK);
				m_digestEngine->Update(inpBuffer, 0, prcRead);
				prcLen += prcRead;
				CalculateProgress(Length, InStream->Position());
			}
		}
	}

	inpBuffer.resize(BLKLEN);

	while (prcLen != ALNLEN)
	{
		prcRead = InStream->Read(inpBuffer, 0, BLKLEN);
		m_digestEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLLEN = Length - prcLen;
		inpBuffer.resize(FNLLEN);
		prcRead = InStream->Read(inpBuffer, 0, FNLLEN);
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
	const size_t BLKLEN = m_digestEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;

	size_t prcLen;

	prcLen = 0;

	if (m_isParallel)
	{
		const size_t PRLBLK = m_digestEngine->ParallelBlockSize();
		if (Length > PRLBLK)
		{
			const size_t PRCLEN = (Length / PRLBLK) * PRLBLK;

			while (prcLen != PRCLEN)
			{
				m_digestEngine->Update(Input, InOffset, PRLBLK);
				InOffset += PRLBLK;
				prcLen += PRLBLK;
				CalculateProgress(Length, InOffset);
			}
		}
	}

	while (prcLen != ALNLEN)
	{
		m_digestEngine->Update(Input, InOffset, BLKLEN);
		InOffset += BLKLEN;
		prcLen += BLKLEN;
		CalculateProgress(Length, InOffset);
	}

	// last block
	if (prcLen != Length)
	{
		const size_t FNLLEN = Length - prcLen;
		m_digestEngine->Update(Input, InOffset, FNLLEN);
		prcLen += FNLLEN;
	}

	// get the hash
	std::vector<byte> chkSum(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

NAMESPACE_PROCESSINGEND
