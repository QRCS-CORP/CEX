#include "DigestStream.h"
#include "DigestFromName.h"
#include "ParallelOptions.h"

NAMESPACE_PROCESSING

using Helper::DigestFromName;
using Exception::ErrorCodes;

const std::string DigestStream::CLASS_NAME("DigestStream");

class DigestStream::DigestStreamState
{
public:

	size_t Interval;
	bool Destroy;
	bool Parallel;

	DigestStreamState(bool Destroyed, bool IsParallel)
		:
		Interval(0),
		Destroy(Destroyed),
		Parallel(IsParallel)
	{
	}

	~DigestStreamState()
	{
		Interval = 0;
		Destroy = false;
		Parallel = false;
	}
};

//~~~Constructor~~~//

DigestStream::DigestStream(Digests DigestType, bool Parallel)
	:
	m_streamState(new DigestStreamState(true, Parallel)),
	m_digestEngine(DigestType != Digests::None ? DigestFromName::GetInstance(DigestType, Parallel) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Digest type can not be none!"), ErrorCodes::IllegalOperation))
{
}

DigestStream::DigestStream(IDigest* Digest)
	:
	m_streamState(new DigestStreamState(true, Digest != nullptr ? Digest->IsParallel() : false)),
	m_digestEngine(Digest != nullptr ? Digest :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Digest can not be null!"), ErrorCodes::IllegalOperation))
{
}

DigestStream::~DigestStream()
{
	if (m_streamState->Destroy)
	{
		if (m_digestEngine != nullptr)
		{
			m_digestEngine.reset(nullptr);
		}
	}
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

	size_t plen = InStream->Length() - InStream->Position();
	CalculateInterval(plen);
	m_digestEngine->Reset();

	return Process(InStream, plen);
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
	size_t itv;

	itv = Length / 100;

	if (itv < m_digestEngine->BlockSize())
	{
		m_streamState->Interval = m_digestEngine->BlockSize();
	}
	else
	{
		m_streamState->Interval = (itv - (itv % m_digestEngine->BlockSize()));
	}

	if (m_streamState->Interval == 0)
	{
		m_streamState->Interval = m_digestEngine->BlockSize();
	}
}

void DigestStream::CalculateProgress(size_t Length, size_t Processed)
{
	double prc;
	double prg;
	size_t blk;

	prc = static_cast<double>(Processed);

	if (Length >= Processed)
	{
		prg = 100.0 * (prc / static_cast<double>(Length));

		if (prg > 100.0)
		{
			prg = 100.0;
		}

		if (m_streamState->Parallel)
		{
			ProgressPercent(static_cast<int>(prg));
		}
		else
		{
			blk = Length / 100;

			if (blk == 0)
			{
				ProgressPercent(static_cast<int>(prg));
			}
			else if (Processed % blk == 0)
			{
				ProgressPercent(static_cast<int>(prg));
			}
			else
			{
				// misra
			}
		}
	}
}

std::vector<byte> DigestStream::Process(IByteStream* InStream, size_t Length)
{
	const size_t BLKLEN = m_digestEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	size_t plen;
	size_t pread;
	std::vector<byte> inp;
	std::vector<byte> tmph;

	plen = 0;
	pread = 0;

	if (m_streamState->Parallel)
	{
		const size_t PRLBLK = m_digestEngine->ParallelBlockSize();

		if (Length > PRLBLK)
		{
			const size_t PRCLEN = (Length / PRLBLK) * PRLBLK;
			inp.resize(PRLBLK);

			while (plen != PRCLEN)
			{
				pread = InStream->Read(inp, 0, PRLBLK);
				m_digestEngine->Update(inp, 0, pread);
				plen += pread;
				CalculateProgress(Length, InStream->Position());
			}
		}
	}

	inp.resize(BLKLEN);

	while (plen != ALNLEN)
	{
		pread = InStream->Read(inp, 0, BLKLEN);
		m_digestEngine->Update(inp, 0, pread);
		plen += pread;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (plen < Length)
	{
		const size_t RMDLEN = Length - plen;
		inp.resize(RMDLEN);
		pread = InStream->Read(inp, 0, RMDLEN);
		m_digestEngine->Update(inp, 0, pread);
		plen += pread;
	}

	// get the hash
	tmph.resize(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(tmph, 0);
	CalculateProgress(Length, plen);

	return tmph;
}

std::vector<byte> DigestStream::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	const size_t BLKLEN = m_digestEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	std::vector<byte> tmph;
	size_t plen;

	plen = 0;

	if (m_streamState->Parallel)
	{
		const size_t PRLBLK = m_digestEngine->ParallelBlockSize();

		if (Length > PRLBLK)
		{
			const size_t PRCLEN = (Length / PRLBLK) * PRLBLK;

			while (plen != PRCLEN)
			{
				m_digestEngine->Update(Input, InOffset, PRLBLK);
				InOffset += PRLBLK;
				plen += PRLBLK;
				CalculateProgress(Length, InOffset);
			}
		}
	}

	while (plen != ALNLEN)
	{
		m_digestEngine->Update(Input, InOffset, BLKLEN);
		InOffset += BLKLEN;
		plen += BLKLEN;
		CalculateProgress(Length, InOffset);
	}

	// last block
	if (plen != Length)
	{
		const size_t RMDLEN = Length - plen;
		m_digestEngine->Update(Input, InOffset, RMDLEN);
		plen += RMDLEN;
	}

	// get the hash
	tmph.resize(m_digestEngine->DigestSize());
	m_digestEngine->Finalize(tmph, 0);
	CalculateProgress(Length, plen);

	return tmph;
}

NAMESPACE_PROCESSINGEND
