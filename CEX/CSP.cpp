#include "CSP.h"
#include "IntUtils.h"

#if defined(CEX_OS_WINDOWS)
#	include <Windows.h>
#	pragma comment(lib, "advapi32.lib")
	HCRYPTPROV m_hProvider = 0;
#elif defined (CEX_OS_ANDROID)
#	include <sys/types.h>
#	include <thread>
#elif defined (CEX_OS_POSIX)
#	include <sys/types.h>
#	include <sys/stat.h>
#	include <fcntl.h>
#	include <unistd.h>
#	include <errno.h>
#	ifndef O_NOCTTY
#		define O_NOCTTY 0
#	endif
#	define CEX_SYSTEM_RNG_DEVICE "/dev/urandom"
#endif

NAMESPACE_PROVIDER

const std::string CSP::CLASS_NAME("CSP");

//~~~Properties~~~//

const Enumeration::Providers CSP::Enumeral()
{
	return Enumeration::Providers::CSP; 
}

const bool CSP::IsAvailable()
{ 
	return m_isAvailable; 
}

const std::string CSP::Name() 
{ 
	return CLASS_NAME;
}

//~~~Constructor~~~//

CSP::CSP()
	:
	m_isAvailable(false)
{
#if defined(CEX_OS_WINDOWS) || defined(CEX_OS_ANDROID) || defined(CEX_OS_POSIX)
	m_isAvailable = true;
#endif
}

CSP::~CSP()
{
	Destroy();
}

//~~~Public Functions~~~//

void CSP::Destroy()
{
}

void CSP::GetBytes(std::vector<byte> &Output)
{
	if (!m_isAvailable)
		throw CryptoRandomException("CSP:GetBytes", "Random provider is not available!");

	size_t prcLen = Output.size();
	size_t prcOffset = 0;

#if defined(CEX_OS_WINDOWS)

	HCRYPTPROV hProvider = NULL;
	if (!::CryptAcquireContextW(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
		throw CryptoRandomException("CSP:GetBytes", "Call to CryptAcquireContext failed; random provider is not available!");

	if (hProvider != NULL)
	{
		BYTE* ptr = (BYTE*)&Output[0];
		if (!::CryptGenRandom(hProvider, (DWORD)prcLen, ptr))
		{
			::CryptReleaseContext(hProvider, 0);
			hProvider = NULL;
			throw CryptoRandomException("CSP:GetBytes", "Call to CryptGenRandom failed; random provider is not available!");
		}
	}

	if (hProvider != NULL)
	{
		CryptReleaseContext(hProvider, 0);
		hProvider = NULL;
	}

#elif defined(CEX_OS_ANDROID)

	try
	{
		do
		{
			size_t prcRmd = Utility::IntUtils::Min(sizeof(uint), prcLen);
			uint rndNum = arc4random();
			Utility::MemUtils::Copy(rndNum, Output, prcOffset, prcRmd);
			prcOffset += prcRmd;
			prcLen -= prcRmd;
		} 
		while (prcLen != 0)
	}
	catch (...)
	{
		throw CryptoRandomException("CSP:GetBytes", "Call to arc4random failed; random provider is not available!");
	}

#else

	int fdHandle = ::open(CEX_SYSTEM_RNG_DEVICE, O_RDONLY | O_NOCTTY);

	if (m_fdHandle < 0)
		throw CryptoRandomException("CSP:GetBytes", "System RNG failed to open RNG device!");

	do
	{
		int rndLen = ::read(fdHandle, &Output[prcOffset], prcLen);

		if (rndLen < 0)
		{
			if (errno == EINTR)
				continue;
			else
				throw CryptoRandomException("CSP:GetBytes", "System RNG read failed error!");
		}
		else if (rndLen == 0)
		{
			throw CryptoRandomException("CSP:GetBytes", "System RNG EOF on device!");
		}

		prcOffset += rndLen;
		prcLen -= rndLen;
	}
	while (prcLen != 0)

	if (fdHandle > 0)
	{
		::close(fdHandle);
		fdHandle = 0;
	}

#endif
}

void CSP::GetBytes(std::vector<byte> &Output, size_t Offset, size_t Length)
{
	CEXASSERT(Offset + Length <= Output.size(), "the array is too small to fulfill this request");

	std::vector<byte> rndData(Length);
	GetBytes(rndData);
	Utility::MemUtils::Copy(rndData, 0, Output, Offset, rndData.size());
}

std::vector<byte> CSP::GetBytes(size_t Length)
{
	std::vector<byte> data(Length);
	GetBytes(data);

	return data;
}

uint CSP::Next()
{
	uint rndNum = 0;
	std::vector<byte> rndData(sizeof(uint));
	GetBytes(rndData);
	Utility::MemUtils::CopyToValue(rndData, 0, rndNum, sizeof(uint));

	return rndNum;
}

void CSP::Reset()
{
}

NAMESPACE_PROVIDEREND