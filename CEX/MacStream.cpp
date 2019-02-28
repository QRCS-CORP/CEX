#include "MacStream.h"
#include "Macs.h"

NAMESPACE_PROCESSING

using Exception::CryptoMacException;
using Enumeration::ErrorCodes;
using Enumeration::Macs;

const std::string MacStream::CLASS_NAME("MacStream");

//~~~Constructor~~~//

MacStream::MacStream(IMac* Mac)
	:
	m_destroyEngine(false),
	m_isDestroyed(false),
	m_isInitialized(false),
	m_macEngine(Mac != nullptr && Mac->Enumeral() != Macs::GMAC ? Mac :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Mac generator can not be null!"), ErrorCodes::IllegalOperation)),
	m_progressInterval(0)
{
}

MacStream::~MacStream()
{
	Destroy();
}

//~~~Accessors~~~//

const std::vector<SymmetricKeySize> MacStream::LegalKeySizes()
{
	return m_macEngine->LegalKeySizes();
}

//~~~Public Functions~~~//

std::vector<byte> MacStream::Compute(IByteStream* InStream)
{
	CEXASSERT(m_isInitialized, "The mac has not been initialized");
	CEXASSERT(InStream->Length() - InStream->Position() > 0, "The input stream is too short");
	CEXASSERT(InStream->CanRead(), "The input stream is set to write only!");

	size_t dataLen;

	dataLen = InStream->Length() - InStream->Position();
	CalculateInterval(dataLen);

	return Process(InStream, dataLen);
}

std::vector<byte> MacStream::Compute(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	CEXASSERT(m_isInitialized, "The mac has not been initialized");
	CEXASSERT((Input.size() - InOffset) > 0 && Length + InOffset <= Input.size(), "The input array is too short");

	size_t dataLen;

	dataLen = Length - InOffset;
	CalculateInterval(dataLen);

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
		m_isInitialized = true;
	}
	catch (CryptoMacException &ex)
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("Initialize"), ex.Message(), ex.ErrorCode());
	}
}

//~~~Private Functions~~~//

void MacStream::CalculateInterval(size_t Length)
{
	size_t interval;

	interval = Length / 100;

	if (interval < m_macEngine->BlockSize())
	{
		m_progressInterval = m_macEngine->BlockSize();
	}
	else
	{
		m_progressInterval = (interval - (interval % m_macEngine->BlockSize()));
	}

	if (m_progressInterval == 0)
	{
		m_progressInterval = m_macEngine->BlockSize();
	}
}

void MacStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double progress = 100.0 * (static_cast<double>(Processed) / Length);
		if (progress > 100.0)
		{
			progress = 100.0;
		}

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

void MacStream::Destroy()
{
	if (!m_isDestroyed)
	{
		m_isDestroyed = true;
		m_isInitialized = false;
		m_progressInterval = 0;

		if (m_destroyEngine)
		{
			m_destroyEngine = false;

			if (m_macEngine != nullptr)
			{
				m_macEngine.reset(nullptr);
			}
		}
		else
		{
			if (m_macEngine != nullptr)
			{
				m_macEngine.release();
			}
		}
	}
}

std::vector<byte> MacStream::Process(IByteStream* InStream, size_t Length)
{
	const size_t BLKLEN = m_macEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;
	size_t prcLen;
	size_t prcRead;

	std::vector<byte> inpBuffer(BLKLEN);

	prcLen = 0;
	prcRead = 0;

	while (prcLen != ALNLEN)
	{
		prcRead = InStream->Read(inpBuffer, 0, BLKLEN);
		m_macEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
		CalculateProgress(Length, InStream->Position());
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLLEN = Length - prcLen;
		inpBuffer.resize(FNLLEN);
		prcRead = InStream->Read(inpBuffer, 0, FNLLEN);
		m_macEngine->Update(inpBuffer, 0, prcRead);
		prcLen += prcRead;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->TagSize());
	m_macEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

std::vector<byte> MacStream::Process(const std::vector<byte> &Input, size_t InOffset, size_t Length)
{
	size_t prcLen;

	const size_t BLKLEN = m_macEngine->BlockSize();
	const size_t ALNLEN = (Length / BLKLEN) * BLKLEN;

	prcLen = 0;

	while (prcLen != ALNLEN)
	{
		m_macEngine->Update(Input, InOffset, BLKLEN);
		InOffset += BLKLEN;
		prcLen += BLKLEN;
		CalculateProgress(Length, prcLen);
	}

	// last block
	if (prcLen < Length)
	{
		const size_t FNLLEN = Length - prcLen;
		m_macEngine->Update(Input, InOffset, FNLLEN);
		prcLen += FNLLEN;
	}

	// get the hash
	std::vector<byte> chkSum(m_macEngine->TagSize());
	m_macEngine->Finalize(chkSum, 0);
	CalculateProgress(Length, prcLen);

	return chkSum;
}

NAMESPACE_PROCESSINGEND
