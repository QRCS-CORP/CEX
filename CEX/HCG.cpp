#include "HCG.h"
#include "ArrayTools.h"
#include "DigestFromName.h"
#include "IntegerTools.h"
#include "MemoryTools.h"
#include "ProviderFromName.h"

NAMESPACE_DRBG

using Tools::ArrayTools;
using Enumeration::DigestConvert;
using Enumeration::DrbgConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Enumeration::SHA2DigestConvert;

const std::vector<char> HCG::CEX_PREFIX = { 0x43, 0x45, 0x58, 0x2D };

class HCG::HcgState
{
public:

	std::vector<byte> Buffer;
	std::vector<byte> Code;
	std::vector<byte> Nonce;

	size_t Cached;
	size_t Counter;
	size_t Rate;
	size_t Reseed;
	size_t Strength;
	size_t Threshold;
	bool IsDestroyed;
	bool IsInitialized;

	HcgState(size_t BlockSize, size_t ReseedMax, bool Destroyed)
		:
		Buffer(BlockSize / 2),
		Code(0),
		Nonce(COUNTER_SIZE),
		Cached(0),
		Counter(0),
		Rate(BlockSize),
		Reseed(0),
		Strength((BlockSize / 4) * 8),
		Threshold(ReseedMax),
		IsDestroyed(Destroyed),
		IsInitialized(false)
	{
	}

	~HcgState()
	{
		Cached = 0;
		Counter = 0;
		Rate = 0;
		Reseed = 0;
		Strength = 0;
		Threshold = 0;
		IsDestroyed = false;
		IsInitialized = false;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(Code, 0, Code.size());
		Code.resize(0);
		MemoryTools::Clear(Nonce, 0, Nonce.size());
	}

	void Reset()
	{
		Cached = 0;
		Counter = 0;
		Reseed = 0;
		MemoryTools::Clear(Buffer, 0, Buffer.size());
		MemoryTools::Clear(Code, 0, Code.size());
		Code.resize(0);
		MemoryTools::Clear(Nonce, 0, Nonce.size());
	}
};

//~~~Constructor~~~//

HCG::HCG(SHA2Digests DigestType, Providers ProviderType)
	:
	DrbgBase(
		Drbgs::HCG,
		(DrbgConvert::ToName(Drbgs::HCG) + std::string("-") + SHA2DigestConvert::ToName(DigestType)),
		DigestType == SHA2Digests::SHA2256 ? 
			std::vector<SymmetricKeySize> {
				SymmetricKeySize(16, COUNTER_SIZE, 8),
				SymmetricKeySize(32, COUNTER_SIZE, 8),
				SymmetricKeySize(64, COUNTER_SIZE, 8)} : 
			std::vector<SymmetricKeySize>{
				SymmetricKeySize(32, COUNTER_SIZE, 40),
				SymmetricKeySize(64, COUNTER_SIZE, 40),
				SymmetricKeySize(128, COUNTER_SIZE, 40)}, 
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_hcgGenerator(DigestType != SHA2Digests::None ? 
		new HMAC(DigestType) :
		throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::HCG), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_hcgProvider(ProviderType == Providers::None ? 
		nullptr : 
		Helper::ProviderFromName::GetInstance(ProviderType)),
	m_hcgState(new HcgState(m_hcgGenerator->BlockSize(), DEF_RESEED, true))
{
}

HCG::HCG(IDigest* Digest, IProvider* Provider)
	:
	DrbgBase(
		Drbgs::HCG,
		(Digest != nullptr ? DrbgConvert::ToName(Drbgs::BCG) + std::string("-") + DigestConvert::ToName(Digest->Enumeral()) :
			throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::HCG), std::string("Constructor"), std::string("The digest can not be null!"), ErrorCodes::IllegalOperation)),
		Digest != nullptr ? 
			(Digest->Enumeral() == Digests::SHA2256 ?
				std::vector<SymmetricKeySize> {
					SymmetricKeySize(16, COUNTER_SIZE, 8),
					SymmetricKeySize(32, COUNTER_SIZE, 8),
					SymmetricKeySize(64, COUNTER_SIZE, 8)} :
				std::vector<SymmetricKeySize>{
					SymmetricKeySize(32, COUNTER_SIZE, 40),
					SymmetricKeySize(64, COUNTER_SIZE, 40),
					SymmetricKeySize(128, COUNTER_SIZE, 40)}) :
				throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::HCG), std::string("Constructor"), std::string("The digest can not be null!"), ErrorCodes::IllegalOperation),
		MAX_OUTPUT,
		MAX_REQUEST,
		MAX_THRESHOLD),
	m_hcgGenerator(Digest != nullptr && (Digest->Enumeral() == Digests::SHA2256 || Digest->Enumeral() != Digests::SHA2512) ? 
		new HMAC(Digest) :
		throw CryptoGeneratorException(DrbgConvert::ToName(Drbgs::HCG), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::IllegalOperation)),
	m_hcgProvider(Provider),
	m_hcgState(new HcgState(m_hcgGenerator->BlockSize(), DEF_RESEED, false))
{
}

HCG::~HCG()
{
	if (m_hcgState->IsDestroyed)
	{
		if (m_hcgGenerator != nullptr)
		{
			m_hcgGenerator.reset(nullptr);
		}

		if (m_hcgProvider != nullptr)
		{
			m_hcgProvider.reset(nullptr);
		}
	}
	else
	{
		if (m_hcgGenerator != nullptr)
		{
			m_hcgGenerator.release();
		}

		if (m_hcgProvider != nullptr)
		{
			m_hcgProvider.release();
		}
	}

	if (m_hcgState != nullptr)
	{
		m_hcgState.reset(nullptr);
	}
}

//~~~Accessors~~~//

const bool HCG::IsInitialized() 
{
	return m_hcgState->IsInitialized; 
}

size_t &HCG::ReseedThreshold()
{
	return m_hcgState->Threshold;
}

const size_t HCG::SecurityStrength()
{
	return m_hcgState->Strength;
}

//~~~Public Functions~~~//

void HCG::Generate(std::vector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void HCG::Generate(SecureVector<byte> &Output)
{
	Generate(Output, 0, Output.size());
}

void HCG::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The generator must be initialized before use!"), ErrorCodes::NotInitialized);
	}
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (Length > MAX_REQUEST)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too large, max request is 64KB!"), ErrorCodes::MaxExceeded);
	}

	Expand(m_hcgGenerator, m_hcgState, Output, OutOffset, Length);

	if (m_hcgProvider != nullptr)
	{
		// update the reseed threshold counter
		m_hcgState->Counter += Length;

		if (m_hcgState->Counter >= ReseedThreshold() || CyclicReseed() == true)
		{
			// update the total reseeds counter
			++m_hcgState->Reseed;

			// maximum number of reseeds exceeded
			if (m_hcgState->Reseed > MaxReseedCount())
			{
				throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
			}

			// refresh the hmac key
			Derive(m_hcgGenerator, m_hcgProvider, m_hcgState);
			// reset the reseed threshold
			m_hcgState->Counter = 0;
		}
	}
}

void HCG::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if ((Output.size() - OutOffset) < Length)
	{
		throw CryptoGeneratorException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}

	std::vector<byte> tmpr(Length);
	Generate(tmpr, 0, tmpr.size());
	SecureMove(tmpr, 0, Output, OutOffset, tmpr.size());
}

void HCG::Initialize(ISymmetricKey &Parameters)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MINKEY_LENGTH)
	{
		throw CryptoGeneratorException(Name(), std::string("Initialize"), std::string("Key size is invalid; check LegalKeySizes for accepted values!"), ErrorCodes::InvalidNonce);
	}
#endif

	m_hcgState->Reset();

	// assign the library name, the formal class name, and the security-strength to the information-code parameter
	ArrayTools::AppendVector(CEX_PREFIX, m_hcgState->Code);
	ArrayTools::AppendString(Name(), m_hcgState->Code);
	ArrayTools::AppendValue(static_cast<ushort>(SecurityStrength()), m_hcgState->Code);
	// add the optional custom distribution code
	ArrayTools::AppendVector(Parameters.Info(), m_hcgState->Code); 

	if (Parameters.KeySizes().IVSize() != 0)
	{
		// copy the nonce into the state counter
		const size_t CTRLEN = IntegerTools::Min(Parameters.KeySizes().IVSize(), m_hcgState->Nonce.size());
		MemoryTools::Copy(Parameters.IV(), 0, m_hcgState->Nonce, 0, CTRLEN);
	}

	// initialize the HMAC
	SymmetricKey kp(Parameters.Key());
	m_hcgGenerator->Initialize(kp);

	// increment the counter by the code size
	IntegerTools::BeIncrease8(m_hcgState->Nonce, static_cast<uint>(m_hcgState->Code.size()));
	// update HMAC with the code and nonce
	m_hcgGenerator->Update(m_hcgState->Code, 0, m_hcgState->Code.size());
	m_hcgGenerator->Update(m_hcgState->Nonce, 0, m_hcgState->Nonce.size());
	// pre-initialize the state buffer
	m_hcgGenerator->Finalize(m_hcgState->Buffer, 0);
	// ready to generate pseudo-random
	m_hcgState->IsInitialized = true;
}

void HCG::Update(const std::vector<byte> &Key)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Key.size()))
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("Key size is invalid; check the key property for accepted value!"), ErrorCodes::InvalidKey);
	}
#endif

	if ((Key.size() < SecurityStrength() / 8) * 2)
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("The key is too small; check the legalkey property for accepted value!"), ErrorCodes::InvalidKey);
	}

	++m_hcgState->Reseed;

	if (m_hcgState->Reseed > MaxReseedCount())
	{
		throw CryptoGeneratorException(Name(), std::string("Update"), std::string("The maximum reseed requests can not be exceeded, re-initialize the generator!"), ErrorCodes::MaxExceeded);
	}

	std::vector<byte> tmpk(m_hcgState->Rate);

	// update the HMAC with the new key
	m_hcgGenerator->Update(Key, 0, Key.size());
	// finalize into the first half of the new HMAC key
	m_hcgGenerator->Finalize(tmpk, 0);

	// fill the buffer
	Fill(m_hcgGenerator, m_hcgState);
	// update HMAC with new state
	m_hcgGenerator->Update(m_hcgState->Buffer, 0, m_hcgState->Buffer.size());
	// finalize the HMAC into the second half of the new key
	m_hcgGenerator->Finalize(tmpk, tmpk.size() / 2);

	// re-key the HMAC
	SymmetricKey kp(tmpk);
	MemoryTools::Clear(tmpk, 0, tmpk.size());
	m_hcgGenerator->Initialize(kp);

	// pre-initialize the buffer
	Fill(m_hcgGenerator, m_hcgState);
}

void HCG::Update(const SecureVector<byte> &Key)
{
	std::vector<byte> tmpk(Key.size());
	MemoryTools::Copy(Key, 0, tmpk, 0, tmpk.size());
	Update(tmpk);
	MemoryTools::Clear(tmpk, 0, tmpk.size());
}

//~~~Private Functions~~~//

void HCG::Derive(std::unique_ptr<HMAC> &Generator, std::unique_ptr<IProvider> &Provider, std::unique_ptr<HcgState> &State)
{
	std::vector<byte> tmpk(State->Rate);

	// fill first half of the HMAC key with new random
	Provider->Generate(tmpk, 0, tmpk.size() / 2);

	// fill the buffer
	Fill(Generator, State);
	// update HMAC with new state
	Generator->Update(State->Buffer, 0, State->Buffer.size());
	// finalize the HMAC into the second half of the new key
	Generator->Finalize(tmpk, tmpk.size() / 2);

	// re-key the HMAC
	SymmetricKey kp(tmpk);
	MemoryTools::Clear(tmpk, 0, tmpk.size());
	Generator->Initialize(kp);

	// pre-initialize the buffer
	Fill(Generator, State);
}

void HCG::Expand(std::unique_ptr<HMAC> &Generator, std::unique_ptr<HcgState> &State, std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (State->Cached < Length)
	{
		// copy remaining bytes from the cache
		if (State->Cached != 0)
		{
			// empty the state buffer
			const size_t BUFPOS = State->Buffer.size() - State->Cached;
			MemoryTools::Copy(State->Buffer, BUFPOS, Output, OutOffset, State->Cached);
			OutOffset += State->Cached;
			Length -= State->Cached;
			State->Cached = 0;
		}

		// loop through the remainder
		while (Length != 0)
		{
			// fill the buffer
			Fill(Generator, State);
			// copy to output
			const size_t RMDLEN = IntegerTools::Min(State->Buffer.size(), Length);
			MemoryTools::Copy(State->Buffer, 0, Output, OutOffset, RMDLEN);
			State->Cached -= RMDLEN;
			OutOffset += RMDLEN;
			Length -= RMDLEN;
		}

		if (State->Cached != 0)
		{
			const size_t BUFPOS = State->Buffer.size() - State->Cached;
			// clear copied bytes from cache
			MemoryTools::Clear(State->Buffer, 0, BUFPOS);
		}
	}
	else
	{
		// copy from the state buffer to output
		const size_t BUFPOS = State->Buffer.size() - State->Cached;
		MemoryTools::Copy(State->Buffer, BUFPOS, Output, OutOffset, Length);
		State->Cached -= Length;
	}
}

void HCG::Fill(std::unique_ptr<HMAC> &Generator, std::unique_ptr<HcgState> &State)
{
	// update HMAC with the current buffer
	Generator->Update(State->Buffer, 0, State->Buffer.size());
	// update HMAC with the info string
	Generator->Update(State->Code, 0, State->Code.size());
	// increment and update HMAC with the counter
	IntegerTools::BeIncrease8(State->Nonce, static_cast<uint>(State->Rate));
	Generator->Update(State->Nonce, 0, State->Nonce.size());
	// generate the block
	Generator->Finalize(State->Buffer, 0);
	// reset the buffer cached length
	State->Cached = State->Buffer.size();
}

NAMESPACE_DRBGEND
