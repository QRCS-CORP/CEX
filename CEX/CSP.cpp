#include "CSP.h"
#include "IntegerTools.h"

#if defined(CEX_OS_WINDOWS)
#	include <tchar.h>
#	include <windows.h>
#	include <Wincrypt.h>
#elif defined (CEX_OS_ANDROID)
#	include <sys/types.h>
#	include <thread>
#elif defined (CEX_OS_POSIX)
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <fcntl.h>
#	include <unistd.h>
#	include <errno.h>
#endif

NAMESPACE_PROVIDER

using Enumeration::ProviderConvert;
using Tools::IntegerTools;
using Tools::MemoryTools;

#if defined(CEX_OS_WINDOWS)
#	pragma comment(lib, "crypt32.lib")
	HCRYPTPROV m_hProvider = 0;
#elif defined (CEX_OS_POSIX)
#	if !defined(O_NOCTTY)
#		define O_NOCTTY 0
#	endif
#	define CEX_SYSTEM_RNG_DEVICE "/dev/urandom"
#endif

//~~~Constructor~~~//

CSP::CSP()
	:
#if defined(CEX_FIPS140_ENABLED)
	m_pvdSelfTest(new ProviderSelfTest),
#endif
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_POSIX)
	ProviderBase(true, Providers::CSP, ProviderConvert::ToName(Providers::CSP))
#else
	ProviderBase(false, Providers::CSP, ProviderConvert::ToName(Providers::CSP))
#endif
{
}

CSP::~CSP()
{
	if (m_pvdSelfTest != nullptr)
	{
		m_pvdSelfTest.reset(nullptr);
	}

#if defined(CEX_OS_WINDOWS)
	m_hProvider = 0;
#endif
}

//~~~Public Functions~~~//

void CSP::Generate(std::vector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(Output.data(), Output.size());
}

void CSP::Generate(std::vector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(&Output[Offset], Length);
}

void CSP::Generate(SecureVector<uint8_t> &Output)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(Output.data(), Output.size());
}

void CSP::Generate(SecureVector<uint8_t> &Output, size_t Offset, size_t Length)
{
	if (IsAvailable() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider is not available!"), ErrorCodes::NotFound);
	}
	if ((Output.size() - Offset) < Length)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The output buffer is too small!"), ErrorCodes::InvalidSize);
	}
	if (FipsTest() == false)
	{
		throw CryptoRandomException(Name(), std::string("Generate"), std::string("The random provider has failed the self test!"), ErrorCodes::InvalidState);
	}

	Generate(&Output[Offset], Length);
}

void CSP::Generate(uint8_t* Output, size_t Length)
{
	size_t poff = 0;

#if defined(CEX_OS_WINDOWS)

	if (Length != 0)
	{
		HCRYPTPROV hprov;

		if (!CryptAcquireContextW(&hprov, 0, 0, PROV_RSA_FULL, (CRYPT_VERIFYCONTEXT | CRYPT_SILENT)))
		{
			throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string("Random provider is not available!"), ErrorCodes::NotFound);
		}

		if (hprov)
		{
			if (!::CryptGenRandom(hprov, static_cast<DWORD>(Length), static_cast<BYTE*>(Output)))
			{
				CryptReleaseContext(hprov, 0);
				hprov = 0;
				throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string("Random provider is not available!"), ErrorCodes::NotFound);
			}
		}

		if (hprov)
		{
			CryptReleaseContext(hprov, 0);
			hprov = 0;
		}
	}

#elif defined(CEX_OS_ANDROID)

	if (Length != 0)
	{
		try
		{
			do
			{
				const size_t PRCRMD = IntegerTools::Min(sizeof(uint32_t), Length);
				uint32_t rnd = arc4random();
				MemoryTools::Copy(rnd, Output, poff, PRCRMD);
				poff += PRCRMD;
				Length -= PRCRMD;
			} while (Length != 0)
		}
		catch (std::exception&)
		{
			throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string(ex.what()), ErrorCodes::UnKnown);
		}
	}

#elif defined(CEX_OS_POSIX)

	if (Length != 0)
	{
		int32_t fdhandle = ::open(CEX_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

		if (fdhandle <= 0)
		{
			throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string("System RNG failed to open RNG device!"), ErrorCodes::NotFound);
		}

		do
		{
			int32_t rlen = ::read(fdhandle, Output + poff, Length);

			if (rlen < 0)
			{
				if (errno == EINTR)
				{
					continue;
				}
				else
				{
					throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string("System RNG read failed error!"), ErrorCodes::BadRead);
				}
			}
			else if (rlen == 0)
			{
				throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string("System RNG read failed error!"), ErrorCodes::BadRead);
			}

			poff += rlen;
			Length -= rlen;
		} 
		while (Length != 0)

		if (fdhandle > 0)
		{
			::close(fdhandle);
			fdhandle = 0;
		}
	}

#else

	throw CryptoRandomException(ProviderConvert::ToName(Providers::CSP), std::string("Generate"), std::string("No system RNG available!"), ErrorCodes::NotFound);

#endif
}

void CSP::Reset()
{
}

//~~~Private Functions~~~//

bool CSP::FipsTest()
{
	bool fail;

	fail = false;

#if defined(CEX_FIPS140_ENABLED)

	SecureVector<uint8_t> smp(m_pvdSelfTest->SELFTEST_LENGTH);

	Generate(smp.data(), smp.size());

	if (!m_pvdSelfTest->SelfTest(smp))
	{
		fail = true;
	}

#endif

	return (fail == false);
}

NAMESPACE_PROVIDEREND
