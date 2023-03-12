#include "CipherStream.h"
#include "BlockCipherFromName.h"
#include "CipherModeFromName.h"
#include "IntegerTools.h"
#include "PaddingFromName.h"
#include "StreamCipherFromName.h"

NAMESPACE_PROCESSING

using Exception::CryptoCipherModeException;
using Exception::ErrorCodes;
using Tools::IntegerTools;
using Tools::MemoryTools;

class CipherStream::CipherState
{
public:

	bool Destroy;
	bool Buffered;
	bool CounterMode;
	bool Encryption;
	bool Initialized;

	CipherState(bool IsCounter, bool Destroyed)
		:
		Destroy(Destroyed),
		Buffered(false),
		CounterMode(IsCounter),
		Encryption(false),
		Initialized(false)
	{

	}

	~CipherState()
	{
		Destroy = false;
		Buffered = false;
		CounterMode = false;
		Encryption = false;
		Initialized = false;
	}
};

const std::string CipherStream::CLASS_NAME("CipherStream");

//~~~Constructor~~~//

CipherStream::CipherStream(BlockCiphers CipherType, CipherModes CipherModeType, PaddingModes PaddingType)
	:
	m_cipherState(new CipherState((CipherModeType == CipherModes::CTR || CipherModeType == CipherModes::ICM), true)),
	m_cipherEngine(CipherModeType != CipherModes::None && CipherType != BlockCiphers::None ? GetCipherMode(CipherType, CipherModeType) :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Digest type can not be none!"), ErrorCodes::IllegalOperation)),
	m_cipherPadding(CipherModeType == CipherModes::CBC || CipherModeType == CipherModes::CFB || CipherModeType == CipherModes::OFB ? GetPaddingMode(PaddingType) : nullptr),
	m_legalKeySizes(m_cipherEngine->LegalKeySizes())
{
}

CipherStream::CipherStream(ICipherMode* Cipher, IPadding* Padding)
	:
	m_cipherState(new CipherState(((Cipher != nullptr && (Cipher->Enumeral() == CipherModes::CTR || Cipher->Enumeral() == CipherModes::ICM)) ? true : false), false)),
	m_cipherEngine(Cipher != nullptr ? Cipher :
		throw CryptoProcessingException(CLASS_NAME, std::string("Constructor"), std::string("Digest type can not be none!"), ErrorCodes::IllegalOperation)),
	m_cipherPadding(Padding),
	m_legalKeySizes(m_cipherEngine->LegalKeySizes())
{
}

CipherStream::~CipherStream()
{
	if (m_cipherState->Destroy)
	{
		if (m_cipherEngine != nullptr)
		{
			m_cipherEngine.reset(nullptr);
		}
		if (m_cipherPadding != nullptr)
		{
			m_cipherPadding.reset(nullptr);
		}
	}

	IntegerTools::Clear(m_legalKeySizes);
}

//~~~Accessors~~~//

bool &CipherStream::IsParallel() 
{
	return m_cipherEngine->ParallelProfile().IsParallel();
}

const std::vector<SymmetricKeySize> CipherStream::LegalKeySizes() 
{ 
	return m_legalKeySizes; 
}

const std::string CipherStream::Name()
{
	return m_cipherEngine->Name();
}

size_t CipherStream::ParallelBlockSize() 
{ 
	return m_cipherEngine->ParallelBlockSize();
}

ParallelOptions &CipherStream::ParallelProfile()
{
	return m_cipherEngine->ParallelProfile();
}

//~~~Public Functions~~~//

void CipherStream::Initialize(bool Encryption, ISymmetricKey &Parameters)
{
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("Initialize"), std::string("The cipher key length is invalid!"), ErrorCodes::InvalidKey);
	}

	try
	{
		m_cipherEngine->ParallelProfile().IsParallel() = IsParallel() && !(m_cipherEngine->Enumeral() == Enumeration::CipherModes::OFB);
		m_cipherEngine->Initialize(Encryption, Parameters);

		m_cipherState->Encryption = Encryption;
		m_cipherState->Initialized = true;
	}
	catch(CryptoCipherModeException &ex)
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("Initialize"), ex.Message(), ex.ErrorCode());
	}
}

void CipherStream::ParallelMaxDegree(size_t Degree)
{
	if (Degree == 0 || Degree % 2 != 0 || Degree > m_cipherEngine->ParallelProfile().ProcessorCount())
	{
		throw CryptoProcessingException(CLASS_NAME, std::string("ParallelMaxDegree"), std::string("Degree setting is invalid"), ErrorCodes::NotSupported);
	}

	m_cipherEngine->ParallelProfile().SetMaxDegree(Degree);
}

void CipherStream::Write(IByteStream* InStream, IByteStream* OutStream)
{
	CEXASSERT(m_cipherState->Initialized, "The cipher has not been initialized");
	CEXASSERT(InStream->Length() - InStream->Position() > 0, "The Input stream is too int16_t");
	CEXASSERT(InStream->CanRead(), "The Input stream is set to write only!");
	CEXASSERT(OutStream->CanRead() || OutStream->CanWrite(), "The Output stream is to read only!");

	BlockTransform(InStream, OutStream);

	if (OutStream->Position() != OutStream->Length())
	{
		OutStream->SetLength(OutStream->Position());
	}
}

void CipherStream::Write(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	CEXASSERT(m_cipherState->Initialized, "The cipher has not been initialized");
	CEXASSERT(Input.size() - InOffset > 0, "The input array is too int16_t");
	CEXASSERT(Input.size() - InOffset <= Output.size() - OutOffset, "The output array is too int16_t!");

	BlockTransform(Input, InOffset, Output, OutOffset);
}

//~~~Private Functions~~~//

void CipherStream::BlockTransform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset)
{
	const size_t INPLEN = Input.size() - InOffset;
	size_t plen;

	plen = 0;

	if (IsParallel())
	{
		const size_t PRLBLK = m_cipherEngine->ParallelBlockSize();
		if (INPLEN > PRLBLK)
		{
			const size_t PRCLEN = (INPLEN % PRLBLK != 0 || m_cipherState->CounterMode || m_cipherState->Encryption) ? (INPLEN / PRLBLK) * PRLBLK : ((INPLEN / PRLBLK) * PRLBLK) - PRLBLK;

			while (plen != PRCLEN)
			{
				m_cipherEngine->Transform(Input, InOffset, Output, OutOffset, PRLBLK);
				InOffset += PRLBLK;
				OutOffset += PRLBLK;
				plen += PRLBLK;
				CalculateProgress(INPLEN, InOffset);
			}
		}
	}

	const size_t BLKLEN = m_cipherEngine->BlockSize();
	const size_t ALNLEN = (m_cipherState->CounterMode || m_cipherState->Encryption) ? (INPLEN / BLKLEN) * BLKLEN : (INPLEN < BLKLEN) ? 0 : ((INPLEN / BLKLEN) * BLKLEN) - BLKLEN;

	if (INPLEN > BLKLEN)
	{
		while (plen != ALNLEN)
		{
			m_cipherEngine->Transform(Input, InOffset, Output, OutOffset, BLKLEN);
			InOffset += BLKLEN;
			OutOffset += BLKLEN;
			plen += BLKLEN;
			CalculateProgress(INPLEN, InOffset);
		}
	}

	// partial
	if (ALNLEN != INPLEN)
	{
		if (m_cipherState->CounterMode)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			std::vector<uint8_t> inp(BLKLEN);
			MemoryTools::Copy(Input, InOffset, inp, 0, FNLLEN);
			std::vector<uint8_t> otp(BLKLEN);
			m_cipherEngine->Transform(inp, 0, otp, 0, FNLLEN);
			MemoryTools::Copy(otp, 0, Output, OutOffset, FNLLEN);
			plen += FNLLEN;
		}
		else if (m_cipherState->Encryption)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			std::vector<uint8_t> inp(BLKLEN);
			MemoryTools::Copy(Input, InOffset, inp, 0, FNLLEN);
			if (FNLLEN != BLKLEN)
			{
				m_cipherPadding->AddPadding(inp, FNLLEN, inp.size());
			}
			plen += BLKLEN;

			if (Output.size() != plen)
			{
				Output.resize(plen);
			}

			m_cipherEngine->EncryptBlock(inp, 0, Output, OutOffset);
		}
		else
		{
			std::vector<uint8_t> otp(BLKLEN);
			m_cipherEngine->DecryptBlock(Input, InOffset, otp, 0);
			const size_t FNLLEN = m_cipherPadding->GetBlockLength(otp);
			MemoryTools::Copy(otp, 0, Output, OutOffset, FNLLEN);
			plen += FNLLEN;

			if (Output.size() != plen)
			{
				Output.resize(plen);
			}
		}
	}

	CalculateProgress(INPLEN, InOffset);
}

void CipherStream::BlockTransform(IByteStream* InStream, IByteStream* OutStream)
{
	const size_t INPLEN = InStream->Length() - InStream->Position();
	size_t plen;
	size_t pread;
	std::vector<uint8_t> inp(0);
	std::vector<uint8_t> otp(0);

	plen = 0;
	pread = 0;

	if (IsParallel())
	{
		const size_t PRLBLK = m_cipherEngine->ParallelBlockSize();
		if (INPLEN > PRLBLK)
		{
			const size_t PRCLEN = (INPLEN % PRLBLK != 0 || m_cipherState->CounterMode || m_cipherState->Encryption) ? (INPLEN / PRLBLK) * PRLBLK : ((INPLEN / PRLBLK) * PRLBLK) - PRLBLK;
			inp.resize(PRLBLK);
			otp.resize(PRLBLK);

			while (plen != PRCLEN)
			{
				pread = InStream->Read(inp, 0, PRLBLK);
				m_cipherEngine->Transform(inp, 0, otp, 0, pread);
				OutStream->Write(otp, 0, pread);
				plen += pread;
				CalculateProgress(INPLEN, OutStream->Position());
			}
		}
	}

	const size_t BLKLEN = m_cipherEngine->BlockSize();
	const size_t ALNLEN = (m_cipherState->CounterMode || m_cipherState->Encryption) ? (INPLEN / BLKLEN) * BLKLEN : (INPLEN < BLKLEN) ? 0 : ((INPLEN / BLKLEN) * BLKLEN) - BLKLEN;
	inp.resize(BLKLEN);
	otp.resize(BLKLEN);

	if (INPLEN > BLKLEN)
	{
		while (plen != ALNLEN)
		{
			pread = InStream->Read(inp, 0, BLKLEN);
			m_cipherEngine->Transform(inp, 0, otp, 0, pread);
			OutStream->Write(otp, 0, pread);
			plen += pread;
			CalculateProgress(INPLEN, OutStream->Position());
		}
	}

	// partial
	if (ALNLEN != INPLEN)
	{
		if (m_cipherState->CounterMode)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			MemoryTools::Clear(otp, 0, otp.size());
			MemoryTools::Clear(inp, 0, inp.size());
			pread = InStream->Read(inp, 0, FNLLEN);
			m_cipherEngine->Transform(inp, 0, otp, 0, pread);
			OutStream->Write(otp, 0, pread);
		}
		else if (m_cipherState->Encryption)
		{
			const size_t FNLLEN = INPLEN - ALNLEN;
			pread = InStream->Read(inp, 0, FNLLEN);
			if (FNLLEN != BLKLEN)
			{
				m_cipherPadding->AddPadding(inp, pread, inp.size());
			}
			m_cipherEngine->EncryptBlock(inp, 0, otp, 0);
			OutStream->Write(otp, 0, BLKLEN);
		}
		else
		{
			InStream->Read(inp, 0, BLKLEN);
			m_cipherEngine->DecryptBlock(inp, 0, otp, 0);
			const size_t FNLLEN = m_cipherPadding->GetBlockLength(otp);
			OutStream->Write(otp, 0, FNLLEN);
		}
	}

	CalculateProgress(INPLEN, OutStream->Position());
}

void CipherStream::CalculateProgress(size_t Length, size_t Processed)
{
	if (Length >= Processed)
	{
		double prc;
		double progress;

		prc = static_cast<double>(Processed);
		progress = 100.0 * (prc / static_cast<double>(Length));

		if (progress > 100.0)
		{
			progress = 100.0;
		}

		if (IsParallel())
		{
			ProgressPercent(static_cast<int32_t>(progress));
		}
		else
		{
			size_t block = Length / 100;
			if (block == 0)
			{
				ProgressPercent(static_cast<int32_t>(progress));
			}
			else if (Processed % block == 0)
			{
				ProgressPercent(static_cast<int32_t>(progress));
			}
			else
			{
				// misra
			}
		}
	}
}

ICipherMode* CipherStream::GetCipherMode(BlockCiphers CipherType, CipherModes CipherModeType)
{
	return Helper::CipherModeFromName::GetInstance(CipherType, CipherModeType);
}

IPadding* CipherStream::GetPaddingMode(PaddingModes PaddingType)
{
	return Helper::PaddingFromName::GetInstance(PaddingType);
}

NAMESPACE_PROCESSINGEND
