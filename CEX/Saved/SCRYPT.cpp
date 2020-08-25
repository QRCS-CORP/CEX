#include "SCRYPT.h"
#include "DigestFromName.h"
#include "Intrinsics.h"
#include "IntegerTools.h"
#include "PBKDF2.h"
#include "ParallelTools.h"
#include "Salsa.h"

/*
keccak
p=input, k=key, F=permutation, h=hash, c=cpucost, m=memcost, s=state

s=F([k] | p) <-mac
s=F(k | [s]) <-kdf

for i... n ->cpucost
{
	s=F(s)

	if (slen < m)
	s += s // mem cost
}

h=F(s)

*/




NAMESPACE_KDF

using Enumeration::KdfConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;
using Tools::ParallelTools;

class SCRYPT::ScryptState
{
public:

	std::vector<byte> Salt;
	std::vector<byte> State;
	size_t Counter;
	size_t CpuCost;
	size_t Parallelization;
	bool IsDestroyed;
	bool IsInitialized;

	ScryptState(size_t StateSize, size_t SaltSize, size_t Cost, size_t Parallel, bool Destroyed)
		:
		Salt(SaltSize),
		State(StateSize),
		Counter(0),
		CpuCost(Cost),
		Parallelization(Parallel),
		IsDestroyed(Destroyed),
		IsInitialized(false)
	{
	}

	~ScryptState()
	{
		Counter = 0;
		CpuCost = 0;
		Parallelization = 0;
		MemoryTools::Clear(Salt, 0, Salt.size());
		Salt.clear();
		MemoryTools::Clear(State, 0, State.size());
		State.clear();
		IsDestroyed = false;
		IsInitialized = false;
	}

	void Reset()
	{
		Counter = 0;
		MemoryTools::Clear(Salt, 0, Salt.size());
		MemoryTools::Clear(State, 0, State.size());
		IsInitialized = false;
	}
};

//~~~Constructor~~~//

SCRYPT::SCRYPT(SHA2Digests DigestType, size_t CpuCost, size_t Parallelization)
	:
	KdfBase(
		(DigestType != SHA2Digests::None ? (DigestType == SHA2Digests::SHA256 ? Kdfs::SCRYPT256 : Kdfs::SCRYPT512) : Kdfs::None),
#if defined(CEX_ENFORCE_LEGALKEY)
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
		(DigestType == SHA2Digests::SHA256 ? 32 : DigestType == SHA2Digests::SHA512 ? 64 : 0),
#else
		MINKEY_LENGTH, 
		MINSALT_LENGTH, 
#endif
		(DigestType == SHA2Digests::SHA256 ? KdfConvert::ToName(Kdfs::SCRYPT256) : DigestType == SHA2Digests::SHA512 ? KdfConvert::ToName(Kdfs::SCRYPT512) : std::string("")),
		(DigestType != SHA2Digests::None ? std::vector<SymmetricKeySize> {
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 32 : 64), 0, 0),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), 0, (DigestType == SHA2Digests::SHA256 ? 32 : 64)),
			SymmetricKeySize((DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 64 : 128), (DigestType == SHA2Digests::SHA256 ? 32 : 64))} :
			std::vector<SymmetricKeySize>(0))),
	m_parallelProfile(64, true, 2048, true),
	m_scryptGenerator(DigestType != SHA2Digests::None ? Helper::DigestFromName::GetInstance(static_cast<Digests>(DigestType)) :
		throw CryptoKdfException(std::string("SCRYPT"), std::string("Constructor"), std::string("The digest type is not supported!"), ErrorCodes::InvalidParam)),
	m_scryptState(new ScryptState(0, 0, CpuCost, Parallelization, true))
{
	if (CpuCost < 1024 || CpuCost % 1024 != 0)
	{
		throw CryptoKdfException(Name(), std::string("Constructor"), std::string("The cpu cost must be greater than 1024 divisible by 1024!"), ErrorCodes::InvalidParam);
	}

	// enable/disable multi-threading
	m_parallelProfile.IsParallel() = Parallelization != 1;

	// set the parallel factor or adjust thread count
	if (Parallelization == 0)
	{
		// auto-set
		m_scryptState->Parallelization = m_parallelProfile.ParallelMaxDegree();
	}
	else if (m_scryptState->Parallelization > 1 && m_scryptState->Parallelization < m_parallelProfile.ParallelMaxDegree())
	{
		// custom degree
		m_parallelProfile.SetMaxDegree(m_scryptState->Parallelization);
	}
	else
	{
		// misra
	}
}

SCRYPT::SCRYPT(IDigest* Digest, size_t CpuCost, size_t Parallelization)
	:
	KdfBase(
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? Kdfs::SCRYPT256 : Kdfs::SCRYPT512) :
			throw CryptoKdfException(std::string("SCRYPT"), std::string("Constructor"), std::string("The digest instance can not be null!"), ErrorCodes::IllegalOperation)),
#if defined(CEX_ENFORCE_LEGALKEY)
		(Digest != nullptr ? Digest->DigestSize() : 0),
		(Digest != nullptr ? Digest->DigestSize() : 0),
#else
		MINKEY_LENGTH,
		MINSALT_LENGTH,
#endif
		(Digest != nullptr ? (Digest->Enumeral() == Digests::SHA256 ? KdfConvert::ToName(Kdfs::SCRYPT256) :
			KdfConvert::ToName(Kdfs::SCRYPT512)) :
			std::string("")),
			(Digest != nullptr ? std::vector<SymmetricKeySize> {
				SymmetricKeySize(Digest->DigestSize(), 0, 0),
				SymmetricKeySize(Digest->BlockSize(), 0, Digest->DigestSize()),
				SymmetricKeySize(Digest->BlockSize(), Digest->BlockSize(), Digest->DigestSize())} :
				std::vector<SymmetricKeySize>(0))),
	m_parallelProfile(64, true, 2048, true),
	m_scryptGenerator((Digest != nullptr && (Digest->Enumeral() == Digests::SHA256 || Digest->Enumeral() == Digests::SHA512)) ? Digest :
		throw CryptoKdfException(std::string("SCRYPT"), std::string("Constructor"), std::string("The digest instance is not supported!"), ErrorCodes::IllegalOperation)),
	m_scryptState(new ScryptState(0, 0, CpuCost, Parallelization, false))
{
	if (CpuCost < 1024 || CpuCost % 1024 != 0)
	{
		throw CryptoKdfException(Name(), std::string("Constructor"), std::string("The cpu cost must be greater than 1024 divisible by 1024!"), ErrorCodes::InvalidParam);
	}

	// enable/disable multi-threading
	m_parallelProfile.IsParallel() = Parallelization != 1;

	// set the parallel factor or adjust thread count
	if (Parallelization == 0)
	{
		// auto-set
		m_scryptState->Parallelization = m_parallelProfile.ParallelMaxDegree();
	}
	else if (m_scryptState->Parallelization > 1 && m_scryptState->Parallelization < m_parallelProfile.ParallelMaxDegree())
	{
		// custom degree
		m_parallelProfile.SetMaxDegree(m_scryptState->Parallelization);
	}
	else
	{
		// invalid parameter
	}
}

SCRYPT::~SCRYPT()
{
	if (m_scryptGenerator != nullptr)
	{
		if (m_scryptState->IsDestroyed)
		{
			m_scryptGenerator.reset(nullptr);
		}
		else
		{
			m_scryptGenerator.release();
		}
	}

	if (m_scryptState != nullptr)
	{
		m_scryptState.reset(nullptr);
	}
}

//~~~Accessors~~~//

size_t &SCRYPT::CpuCost()
{
	return m_scryptState->CpuCost;
}

const bool SCRYPT::IsInitialized()
{
	return m_scryptState->IsInitialized; 
}

const bool SCRYPT::IsParallel()
{ 
	return m_parallelProfile.IsParallel(); 
}

size_t &SCRYPT::Parallelization()
{
	return m_scryptState->Parallelization;
}

ParallelOptions &SCRYPT::ParallelProfile() 
{ 
	return m_parallelProfile;
}

//~~~Public Functions~~~//

void SCRYPT::Generate(std::vector<byte> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_scryptState->Counter + (Output.size() / m_scryptGenerator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_scryptState, m_parallelProfile, m_scryptGenerator);
}

void SCRYPT::Generate(SecureVector<byte> &Output)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (m_scryptState->Counter + (Output.size() / m_scryptGenerator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, 0, Output.size(), m_scryptState, m_parallelProfile, m_scryptGenerator);
}

void SCRYPT::Generate(std::vector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (m_scryptState->Counter + (Length / m_scryptGenerator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, OutOffset, Length, m_scryptState, m_parallelProfile, m_scryptGenerator);
}

void SCRYPT::Generate(SecureVector<byte> &Output, size_t OutOffset, size_t Length)
{
	if (IsInitialized() == false)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The generator has not been initialized!"), ErrorCodes::NotInitialized);
	}
	if (Output.size() - OutOffset < Length)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("The output buffer is too short!"), ErrorCodes::InvalidSize);
	}
	if (m_scryptState->Counter + (Length / m_scryptGenerator->DigestSize()) > MAXGEN_REQUESTS)
	{
		throw CryptoKdfException(Name(), std::string("Generate"), std::string("Request exceeds maximum allowed output!"), ErrorCodes::MaxExceeded);
	}

	Expand(Output, OutOffset, Length, m_scryptState, m_parallelProfile, m_scryptGenerator);
}

void SCRYPT::Initialize(ISymmetricKey &Parameters)
{
#if defined(CEX_ENFORCE_LEGALKEY)
	if (!SymmetricKeySize::Contains(LegalKeySizes(), Parameters.KeySizes().KeySize()))
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be one of the LegalKeySizes in length!"), ErrorCodes::InvalidKey);
	}
#else
	if (Parameters.KeySizes().KeySize() < MinimumKeySize())
	{
		throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Invalid key size, the key length must be at least MinimumKeySize in length!"), ErrorCodes::InvalidKey);
	}
#endif

	if (IsInitialized() == true)
	{
		Reset();
	}

	// add the key to the state
	m_scryptState->State.resize(Parameters.KeySizes().KeySize());
	MemoryTools::Copy(Parameters.Key(), 0, m_scryptState->State, 0, m_scryptState->State.size());

	if (Parameters.KeySizes().IVSize() + Parameters.KeySizes().InfoSize() != 0)
	{
		if (Parameters.KeySizes().IVSize() + Parameters.KeySizes().InfoSize() < MinimumSaltSize())
		{
			throw CryptoKdfException(Name(), std::string("Initialize"), std::string("Salt value is too small, must be at least 4 bytes in length!"), ErrorCodes::InvalidSalt);
		}

		m_scryptState->Salt.resize(Parameters.KeySizes().IVSize() + Parameters.KeySizes().InfoSize());

		// add the nonce param to salt
		if (Parameters.KeySizes().IVSize() > 0)
		{
			MemoryTools::Copy(Parameters.IV(), 0, m_scryptState->Salt, 0, m_scryptState->Salt.size());
		}

		// add info as extension of salt
		if (Parameters.KeySizes().InfoSize() > 0)
		{
			MemoryTools::Copy(Parameters.Info(), 0, m_scryptState->Salt, Parameters.KeySizes().IVSize(), Parameters.KeySizes().InfoSize());
		}
	}

	m_scryptState->IsInitialized = true;
}

void SCRYPT::Reset()
{
	m_scryptState->Reset();
	//m_scryptGenerator->Reset();
	m_scryptState->IsInitialized = false;
}

//~~~Private Functions~~~//

void SCRYPT::Expand(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ScryptState> &State, ParallelOptions &Options, std::unique_ptr<IDigest> &Generator)
{
	const size_t MFLEN = MEMORY_COST * 128;
	const size_t KEYLEN = State->Parallelization * MFLEN;
	const size_t SKLEN = KEYLEN >> 2;
	const size_t CPUCST = State->CpuCost;
	const size_t MFLWRD = MFLEN >> 2;
	const size_t PRLBLK = SKLEN / Options.ParallelMaxDegree();
	std::vector<byte> tmpk(KEYLEN);
	std::vector<uint> statek(SKLEN);
	size_t toff;

	Extract(tmpk, 0, tmpk.size(), State->State, State->Salt, Generator);

#if defined(__AVX__)
	for (size_t k = 0; k < 2 * MEMORY_COST * State->Parallelization; ++k)
	{
		for (size_t i = 0; i < 16; i++)
		{
			statek[k * 16 + i] = IntegerTools::LeBytesTo32(tmpk, (k * 16 + (i * 5 % 16)) * 4);
		}
	}
#else
	IntegerTools::BlockToLe(tmpk, 0, statek, 0, tmpk.size());
#endif

	toff = 0;

	if (Options.IsParallel() && PRLBLK >= MFLWRD)
	{
		ParallelTools::ParallelFor(0, Options.ParallelMaxDegree(), [CPUCST, &statek, PRLBLK, MFLWRD](size_t i)
		{
			for (size_t j = 0; j < PRLBLK; j += MFLWRD)
			{
				MixState(statek, (i * PRLBLK) + j, CPUCST);
			}
		});

		toff = PRLBLK * Options.ParallelMaxDegree();
	}

	if (toff != SKLEN)
	{
		for (size_t i = toff; i < SKLEN; i += MFLWRD)
		{
			MixState(statek, i, State->CpuCost);
		}
	}

#if defined(__AVX__)
	for (size_t k = 0; k < 2 * MEMORY_COST * State->Parallelization; ++k)
	{
		for (size_t i = 0; i < 16; i++)
		{
			IntegerTools::Le32ToBytes(statek[k * 16 + i], tmpk, (k * 16 + (i * 5 % 16)) * 4);
		}
	}
#else
	IntegerTools::LeToBlock(statek, 0, tmpk, 0, tmpk.size());
#endif

	Extract(Output, OutOffset, Length, State->State, tmpk, Generator);
	++State->Counter;
}

void SCRYPT::Expand(SecureVector<byte> &Output, size_t OutOffset, size_t Length, std::unique_ptr<ScryptState> &State, ParallelOptions &Options, std::unique_ptr<IDigest> &Generator)
{
	std::vector<byte> tmps(Length);
	Expand(tmps, OutOffset, Length, State, Options, Generator);
	SecureMove(tmps, 0, Output, OutOffset, tmps.size());
}

void SCRYPT::Extract(std::vector<byte> &Output, size_t OutOffset, size_t Length, std::vector<byte> &Key, std::vector<byte> &Salt, std::unique_ptr<IDigest> &Generator)
{
	Kdf::PBKDF2 kdf(static_cast<SHA2Digests>(Generator->Enumeral()), 1);
	Cipher::SymmetricKey kp(Key, Salt);

	kdf.Initialize(kp);
	kdf.Generate(Output, OutOffset, Length);
	Generator->Reset();
}

void SCRYPT::MixBlock(std::vector<uint> &X, std::vector<uint> &Y)
{
	std::vector<uint> tmpx(16);
	MemoryTools::Copy(X, X.size() - 16, tmpx, 0, 16 * sizeof(uint));

	for (size_t i = 0; i < 2 * MEMORY_COST; i += 2)
	{
		MemoryTools::XOR(X, i * 16, tmpx, 0, tmpx.size() * sizeof(uint));

#if defined(__AVX__)
		Cipher::Stream::Salsa::PermuteP512V(tmpx);
#else
		Cipher::Stream::Salsa::PermuteP512C(tmpx);
#endif

		MemoryTools::Copy(tmpx, 0, Y, i * 8, 16 * sizeof(uint));
		MemoryTools::XOR(X, (i + 1) * 16, tmpx, 0, tmpx.size() * sizeof(uint));

#if defined(__AVX__)
		Cipher::Stream::Salsa::PermuteP512V(tmpx);
#else
		Cipher::Stream::Salsa::PermuteP512C(tmpx);
#endif

		MemoryTools::Copy(tmpx, 0, Y, (i * 8) + (MEMORY_COST * 16), 16 * sizeof(uint));
	}

	MemoryTools::Copy(Y, 0, X, 0, Y.size() * sizeof(uint));
}

void SCRYPT::MixState(std::vector<uint> &State, size_t StateOffset, size_t N)
{
	const size_t BLKCNT = MEMORY_COST * 32;
	const uint NMASK = static_cast<uint>(N) - 1;
	std::vector<std::vector<uint>> tmpv(N);
	std::vector<uint> tmpx(BLKCNT);
	std::vector<uint> tmpy(BLKCNT);
	size_t i;
	uint j;

	MemoryTools::Copy(State, StateOffset, tmpx, 0, BLKCNT * sizeof(uint));

	for (i = 0; i < N; ++i)
	{
		tmpv[i] = tmpx;
		MixBlock(tmpx, tmpy);
	}

	for (i = 0; i < N; ++i)
	{
		j = tmpx[BLKCNT - 16] & NMASK;
		MemoryTools::XOR(tmpv[j], 0, tmpx, 0, tmpx.size() * sizeof(uint));
		MixBlock(tmpx, tmpy);
	}

	MemoryTools::Copy(tmpx, 0, State, StateOffset, BLKCNT * sizeof(uint));
}

NAMESPACE_KDFEND
