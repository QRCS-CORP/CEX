#include "MacStream.h"
#include "MacFromName.h"

NAMESPACE_PROCESSING

using Exception::CryptoMacException;
using Enumeration::ErrorCodes;
using Helper::MacFromName;
using Enumeration::Macs;

const std::string MacStream::CLASS_NAME("MacStream");

//~~~Constructor~~~//

class MacStream::MacStreamState
{
public:

	size_t Interval;
	bool Destroy;
	bool Initialized;

	MacStreamState(bool Destroyed)
		:
		Interval(0),
		Destroy(Destroyed),
		Initialized(false)
	{
	}

	~MacStreamState()
	{
		Interval = 0;
		Destroy = false;
		Initialized = false;
	}
};

MacStream::MacStream(Macs MacType)
	:
	m_streamState(new MacStreamState(true)),
	m_macEngine(MacType != Macs::None && MacType != Macs::GMAC ? MacFromName::GetInstance(MacType) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("MAC type can not be none!"), ErrorCodes::InvalidParam))
{
}

MacStream::MacStream(IMac* Mac)
	:
	m_streamState(new MacStreamState(false)),
	m_macEngine(Mac != nullptr && Mac->Enumeral() != Macs::GMAC ? Mac :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Mac generator can not be null!"), ErrorCodes::IllegalOperation))
{
}

MacStream::~MacStream()
{
	if (m_streamState->Destroy)
	{
		if (m_macEngine != nullptr)
		{
			m_macEngine.reset(nullptr);
		}
	}
}

//~~~Accessors~~~//

const std::vector<SymmetricKeySize> MacStream::LegalKeySizes()
{
	return m_macEngine->LegalKeySizes();
}

//~~~Public Functions~~~//

std::vector<byte> MacStream::Compute(IByteStream* InStream)
{
	CEXASSERT(m_streamState->Initialized, "The mac has not been initialized");
	CEXASSERT(InStream->Length() - InStream->Position() > 0, "The input stream is too short");
	CEXASSERT(InStream->CanRead(), "The input stream is set to write only!");

	size_t plen;

	plen = InStream->Length() - InStream->Position();
	CalculateInterval(plen);

	return Process(InStream, plen);
}

std::vector<byte> MacStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(m_streamState->Initialized, "The mac has not been initialized");
	CEXASSERT((Input.size() - InOffset) > 0 && Length + InOffset <= Input.size(), "The input array is too short");

	size_t plen;

	plen = Length - InOffset;
	CalculateInterval(plen);

	return Process(Input, InOffset, Length);
}

void MacStream::Initialize(ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("Initialize"), std::string("Mac Key has invalid length!"), ErrorCodes::InvalidKey);
	}

	try
	{
		m_macEngine->Initialize(Parameters);
		m_streamState->Initialized = true;
	}
	catch (CryptoMacException &ex)
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("Initialize"), ex.Message(), ex.ErrorCode());
	}
}

//~~~Private Functions~~~//

void MacStream::CalculateInterval(size_t Length)
{
	size_t itv;

	itv = Length / 100;

	if (itv < m_macEngine->BlockSize())
	{
		m_streamState->Interval = m_macEngine->BlockSize();
	}
	else
	{
		m_streamState->Interval = (itv - (itv % m_macEngine->BlockSize()));
	}

	if (m_streamState->Interval == 0)
	{
		m_streamState->Interval = m_macEngine->BlockSize();
	}
}

void MacStream::CalculateProgress(size_t Length, size_t Processed)
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

std::vector<byte> MacStream::Process(IByteStream* InStream, size_t Length)
{
	const size_t BLKLEN = m_macEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	std::vector<byte> tmph;
	size_t plen;
	size_t pread;

	std::vector<byte> inpBuffer(BLKLEN);

	plen = 0;
	pread = 0;

	while (plen != ALNLEN)
	{
		pread = InStream->Read(inpBuffer, 0, BLKLEN);
		m_macEngine->Update(inpBuffer, 0, pread);
		plen += pread;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (plen < Length)
	{
		const size_t FNLLEN = Length - plen;
		inpBuffer.resize(FNLLEN);
		pread = InStream->Read(inpBuffer, 0, FNLLEN);
		m_macEngine->Update(inpBuffer, 0, pread);
		plen += pread;
	}

	// get the hash
	tmph.resize(m_macEngine->TagSize());
	m_macEngine->Finalize(tmph, 0);
	CalculateProgress(Length, plen);

	return tmph;
}

std::vector<byte> MacStream::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	const size_t BLKLEN = m_macEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	std::vector<byte> tmph;
	size_t plen;

	plen = 0;

	while (plen != ALNLEN)
	{
		m_macEngine->Update(Input, InOffset, BLKLEN);
		InOffset += BLKLEN;
		plen += BLKLEN;
		CalculateProgress(Length, plen);
	}

	// last block
	if (plen < Length)
	{
		const size_t FNLLEN = Length - plen;
		m_macEngine->Update(Input, InOffset, FNLLEN);
		plen += FNLLEN;
	}

	// get the hash
	tmph.resize(m_macEngine->TagSize());
	m_macEngine->Finalize(tmph, 0);
	CalculateProgress(Length, plen);

	return tmph;
}

NAMESPACE_PROCESSINGEND
