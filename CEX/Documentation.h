#ifndef CEX_DOCUMENTATION_H
#define CEX_DOCUMENTATION_H

#error Documentation only!

#include "CexDomain.h"

// start doxygen main //
/*! \mainpage A programmers guide to the CEX++ Cryptographic library

\section intro_sec Welcome
Welcome to the CEX++ Cryptographic Library, version 1.0.0.7 (A7).
\brief
CEX is a library built for both speed and maximum security.
This help package contains details on the cryptographic primitives used in the library, their uses, and code examples.

\section road_map Road Map
The current version is <B>1.0.0.7f</B> (A7 version), which are the major, minor, patch, and release codes, and the update segment letter. \n
\brief

\author    John Underhill
\version   1.0.0.7f
\date      Januray 14, 2018
\copyright GPL version 3 license (GPLv3)

<B>Trajectory</B> \n \n

The current version is 1.0.0.7f (A7 version), which are the major, minor, patch, and release codes. \n \n

<B>Current Release 1.0.0.7f (version A7):</B> \n

The Dilithium asymmetric signature scheme \n
The SPHINCS+ asymmetric signature scheme \n
The NTRU Prime asymmetric cipher \n
Authenticated Threefish-256/512/1024 stream ciphers \n
Authenticated ChaCha-256/512 stream ciphers \n
The cSHAKE option (RSX) integrated into RHX/AHX \n
Asymmetric ciphers updated to the NIST PQ Round 1 versions \n

<B>Planned Release 1.1.0.1</B> \n
RingLWE \n
McEliece \n
ModuleLWE \n
NTRU \n
RSA \n
RSA-SIG \n
Dilithium \n
SPHINCS+ \n \n

<B>Planned Release 1.2.0.1</B> \n
TLS \n
STM-KEX \n
Android/iOS/Linux Compatability \n
DLL API \n \n

<B>History</B> \n \n

<B>Version 1.0.0.6, June 17, 2018 (with partial 1.0.0.7 release, Sept 27)</B> \n
Added the NTRU Prime asymmetric cipher \n
Added the RSX symmetric cipher \n
Added the Threefish 256/512/1024 symmetric ciphers \n
Added ChaCha512-P80 symmetric cipher \n
Asymmetric ciphers updated to the NIST PQ Round 1 versions \n \n

<B>Version 1.0.0.5, February 22, 2018</B> \n
Added the ModuleLWE asymmetric cipher \n
Added asymmetric cipher Encapsulate/Decapsulate api \n
Added the 128/256/512/1024 SHAKE XOF function \n
Updates to random providers and Prngs \n
The library is now Misra C++ 2014 compliant \n \n

<B>Version 1.0.0.4, November 11, 2017</B> \n
Added the McEliece asymmetric cipher \n
Added the 1024bit Keccak digest \n
Added the Poly1305 Message Authentication Code generator \n
The library is now SEI-CERT compliant (Misra compliance by 1.0.0.5) \n
Full coding standards sweep of the library \n
Integration of std::array and std::unique_ptr throughout \n
A full optimization cycle completed \n \n

<B>Version 1.0.0.3, June 30, 2017</B> \n
Added asymmetric cipher interfaces and framework \n
Added RingLWE asymmetric cipher \n
Added the Auto Collection seed Provider (ACP) \n
Addition of the HCR prng \n
Renaming of the drbgs to xCG format: BCG, DCG, and HCG; Block cipher Counter Generator, Digest and HMAC Counter Generators \n
Overhaul of SecureRandom and prng classes \n \n

<B>Version 1.0.0.2: April 23, 2017</B> \n
Last of 1.0 sweep of the symmetric library before the second half of the project engages, with thousands of changes made throughout, and the addition of (!experimental) AVX512 support. \n
Added a vectorized MemoryTools class, with SIMD 128/256/512 copy, clear, set-value, and xor functions. \n
Integrated vectorized replacements for memcpy, xor, and memset throughout, including cipher mode support for AVX512, (I don't have a xeon to test this, maybe you can help?). \n
Reformatting of headers (inline accessors removed and the override hint added). \n
Many small TODOs finished, api synchronized, and formatting and documentation changes throughout. \n \n

<B>Version 1.0: March 28, 2017</B> \n
The first official release of the library, (ciphers and protocols are now tested, documented, and ready for deployment). \n
Completed Code and Help review cycles. \n
Added parallelized HMAC implementation. \n
Added multi-threaded Tree Hashing to all Skein and Keccak digest implementations. \n
Added SIMD parallelization to Skein512. \n
Rewrote SHA-2 paralellized tree hashing and added support for the SHA-NI SIMD to SHA-256. \n
Added a multi-threaded and SIMD parallelized implementation of the SCRYPT key derivation function. \n \n

\section intro_link Links
The CEX++ Help pages: http://www.vtdev.com/CEX-Plus/Help/html/index.html  \n
CEX++ on Github: https://github.com/Steppenwolfe65/CEX  \n
CEX .NET on Github: https://github.com/Steppenwolfe65/CEX-NET  \n
The Code Project article on CEX .NET: http://www.codeproject.com/Articles/828477/Cipher-EX-V
*/
// end doxygen main //



/*!
*  \addtogroup CEX
*  @{
*  @brief Root Namespace
*/
NAMESPACE_ROOT
	class CpuDetect {};
	class Mutex {};
	class ParallelOptions {};
	class SecureMemory {};
	class SecureVector {};

	/*!
	*  \addtogroup Asymmetric
	*  @{
	*  @brief Asymmetric Ciphers Namespace
	*/
	NAMESPACE_ASYMMETRIC
		class AsymmetricKey {};
		class AsymmetricKeyPair {};
		class IAsymmetricKey {};
		class IAsymmetricKeyPair {};

		/*!
		*  \addtogroup Encrypt
		*  @{
		*  @brief Asymmetric Ciphers Namespace
		*/
		NAMESPACE_ASYMMETRICENCRYPT
			/*!
			*  \addtogroup McEliece
			*  @{
			*  @brief The McEliece Cipher Namespace
			*/
			NAMESPACE_MCELIECE
				class McEliece {};
			NAMESPACE_MCELIECEEND
			/*! @} */

			/*!
			*  \addtogroup ModuleLWE
			*  @{
			*  @brief The McEliece Cipher Namespace
			*/
			NAMESPACE_MODULELWE
				class ModuleLWE {};
			NAMESPACE_MODULELWEEND
			/*! @} */

			/*!
			*  \addtogroup NTRU
			*  @{
			*  @brief The NTRU Cipher Namespace
			*/
			NAMESPACE_NTRU
				class NTRU {};
			NAMESPACE_NTRUEND
			/*! @} */

			/*!
			*  \addtogroup RingLWE
			*  @{
			*  @brief The RingLWE Cipher Namespace
			*/
			NAMESPACE_RINGLWE
				class RingLWE {};
			NAMESPACE_RINGLWEEND
			/*! @} */
		NAMESPACE_ASYMMETRICENCRYPTEND
		/*! @} */

		/*!
		*  \addtogroup Sign
		*  @{
		*  @brief Asymmetric Signature Namespace
		*/
		NAMESPACE_ASYMMETRICSIGN

			/*!
			*  \addtogroup Dilithium
			*  @{
			*  @brief The Dilithium asymmetric signature scheme Namespace
			*/
			NAMESPACE_DILITHIUM
				class Dilithium {};
			NAMESPACE_DILITHIUMEND
			/*! @} */

			/*!
			*  \addtogroup Sphincs
			*  @{
			*  @brief The SPHINCS+ asymmetric signature scheme Namespace
			*/
			NAMESPACE_SPHINCS
				class Sphincs {};
			NAMESPACE_SPHINCSEND
			/*! @} */

		NAMESPACE_ASYMMETRICSIGNEND
		/*! @} */

	NAMESPACE_ASYMMETRICEND
	/*! @} */


	/*!
	*  \addtogroup Cipher
	*  @{
	*  @brief Cryptographic Cipher Namespace
	*/
	NAMESPACE_CIPHER
		class ISymmetricKey {};
		class SymmetricKeyGenerator {};
		class SymmetricKey {};
		class SymmetricKeySize {};
		class SymmetricSecureKey {};

		/*!
		*  \addtogroup Block
		*  @{
		*  @brief Symmetric Block Cipher Namespace
		*/
		NAMESPACE_BLOCK
			class AHX {};
			class IBlockCipher {};
			class RHX {};
			class SHX {};

			/*!
			*  \addtogroup Mode
			*  @{
			*  @brief Symmetric Block Cipher Mode Namespace
			*/
			NAMESPACE_MODE
				class CBC {};
				class CFB {};
				class CTR {};
				class EAX {};
				class ECB {};
				class GCM {};
				class IAeadMode {};
				class ICipherMode {};
				class ICM {};
				class OCB {};
				class OFB {};
			NAMESPACE_MODEEND
			/*! @} */

			/*!
			*  \addtogroup Padding
			*  @{
			*  @brief Symmetric Block Cipher Padding Namespace
			*/
			NAMESPACE_PADDING
				class IPadding {};
				class ESP {};
				class PKCS7 {};
				class X923 {};
				class ZeroOne {};
			NAMESPACE_PADDINGEND
			/*! @} */

		NAMESPACE_BLOCKEND
		/*! @} */

		/*!
		*  \addtogroup Stream
		*  @{
		*  @brief Symmetric Stream Cipher Namespace
		*/
		NAMESPACE_STREAM
			class ACS {};
			class ChaCha256 {};
			class ChaCha512 {};
			class IStreamCipher {};
			class Threefish256 {};
			class Threefish512 {};
			class Threefish1024 {};
		NAMESPACE_STREAMEND
		/*! @} */

	NAMESPACE_CIPHEREND
	/*! @} */

	/*!
	*  \addtogroup Digest
	*  @brief Cryptographic Hash Classes
	*  @{
	*/
	NAMESPACE_DIGEST
		class Blake2 {};
		class Blake512 {};
		class Blake256 {};
		class Blake2Params {};
		class IDigest {};
		class Keccak {};
		class Keccak256 {};
		class Keccak512 {};
		class Keccak1024 {};
		class KeccakParams {};
		class KeccakState {};
		class SHA2 {};
		class SHA256 {};
		class SHA512 {};
		class SHA2Params {};
		class Skein {};
		class Skein256 {};
		class Skein512 {};
		class Skein1024 {};
		class SkeinParams {};
		class SkeinUbiTweak {};
	NAMESPACE_DIGESTEND
	/*! @} */

	/*!
	*  \addtogroup Drbg
	*  @{
	*  @brief Deterministic Random Byte Generators
	*/
	NAMESPACE_DRBG
		class BCG {};
		class CSG {};
		class IDrbg {};
		class HCG {};
	NAMESPACE_DRBGEND
	/*! @} */

	/*!
	*  \addtogroup Enumeration
	*  @{
	*  @brief Cryptographic Enumerations
	*/
	NAMESPACE_ENUMERATION
		enum class AeadModes {};
		enum class AsymmetricEngines {};
		enum class AsymmetricKeyTypes {};
		enum class AsymmetricTransforms {};
		enum class Authenticators {};
		enum class BlockCiphers {};
		enum class BlockCipherExtensions {};
		enum class BlockSizes {};
		enum class CipherModes {};
		enum class CpuCores {};
		enum class Digests {};
		enum class DilithiumParameters {};
		enum class Drbgs {};
		enum class IVSizes {};
		enum class Kdfs {};
		enum class KeySizes {};
		enum class Macs {};
		enum class MLWEParameters {};
		enum class MPKCParameters {};
		enum class NTRUParameters {};
		enum class PaddingModes {};
		enum class Prngs {};
		enum class Providers {};
		enum class RLWEParameters {};
		enum class RoundCounts {};
		enum class SHA2Digests {};
		enum class ShakeModes {};
		enum class SimdIntegers {};
		enum class SimdProfiles {};
		enum class SkeinUbiType {};
		enum class SphincsParameters {};
		enum class StreamAuthenticators {};
		enum class StreamCiphers {};
		enum class StreamModes {};
		enum class SymmetricCiphers {};
		enum class ThreefishModes {};
	NAMESPACE_ENUMERATIONEND
	/*! @} */

	/*!
	*  \addtogroup Exception
	*  @{
	*  @brief Cryptographic Exceptions
	*/
	NAMESPACE_EXCEPTION
		class CryptoAsymmetricException {};
		class CryptoAuthenticationFailure {};
		class CryptoCipherModeException {};
		class CryptoDigestException {};
		class CryptoException {};
		class CryptoGeneratorException {};
		class CryptoKdfException {};
		class CryptoMacException {};
		class CryptoPaddingException {};
		class CryptoProcessingException {};
		class CryptoRandomException {};
		class CryptoSymmetricCipherException {};
	NAMESPACE_EXCEPTIONEND
	/*! @} */

	/*!
	*  \addtogroup Helper
	*  @{
	*  @brief Cryptographic Helper Classes
	*/
	NAMESPACE_HELPER
		class AeadModeFromName {};
		class BlockCipherFromName {};
		class CipherFromDescription {};
		class CipherModeFromName {};
		class DigestFromName {};
		class DrbgFromName {};
		class KdfFromName {};
		class MacFromDescription {};
		class PaddingFromName {};
		class PrngFromName {};
		class ProviderFromName {};
		class SecureStream {};
		class StreamCipherFromName {};
	NAMESPACE_HELPEREND
	/*! @} */

	/*!
	*  \addtogroup IO
	*  @{
	*  @brief IO Processors
	*/
	NAMESPACE_IO
		class BitConverter {};
		class FileStream {};
		class IByteStream {};
		class MemoryStream {};
		class SecureStream {};
		enum class SeekOrigin {};
		class StreamReader {};
		class StreamWriter {};
	NAMESPACE_IOEND
	/*! @} */

	/*!
	*  \addtogroup KDF
	*  @{
	*  @brief Key Derivation Functions
	*/
	NAMESPACE_KDF
		class HKDF {};
		class IKdf {};
		class KDF2 {};
		class PBKDF2 {};
		class SCRYPT {};
		class SHAKE {};
	NAMESPACE_KDFEND
	/*! @} */

	/*!
	*  \addtogroup Mac
	*  @{
	*  @brief Message Authentication Code Generators
	*/
	NAMESPACE_MAC
		class CMAC {};
		class GMAC {};
		class HMAC {};
		class IMac {};
		class KMAC {};
		class Poly1305 {};
	NAMESPACE_MACEND
	/*! @} */

	//NAMESPACE_NETWORK
	//NAMESPACE_NETWORKEND

	/*!
	*  \addtogroup Numeric
	*  @{
	*  @brief SIMD and Big Integer Namespace
	*/
	NAMESPACE_NUMERIC
		class Donna128 {};
		class UInt128 {};
		class UInt256 {};
		class UInt512 {};
		class ULong256 {};
		class ULong512 {};
		class UShort128 {};
	NAMESPACE_NUMERICEND
	/*! @} */

	/*!
	*  \addtogroup Prng
	*  @{
	*  @brief Pseudo Random Number Generators
	*/
	NAMESPACE_PRNG
		class BCR {};
		class DCR {};
		class IPrng {};
		class PBR {};
		class SecureRandom {};
	NAMESPACE_PRNGEND
	/*! @} */

	/*!
	*  \addtogroup Processing
	*  @{
	*  @brief Cryptographic Processing Namespace
	*/
	NAMESPACE_PROCESSING
		class CipherDescription {};
		class CipherStream {};
		class DigestStream {};
		class MacDescription {};
		class MacStream {};
	NAMESPACE_PROCESSINGEND
	/*! @} */

	/*!
	*  \addtogroup Provider
	*  @{
	*  @brief Entropy source collectors and concentrators
	*/
	NAMESPACE_PROVIDER
		class CJP {};
		class CSP {};
		class ECP {};
		class IProvider {};
		class RDP {};
	NAMESPACE_PROVIDEREND
	/*! @} */

	/*!
	*  \addtogroup Event Routing
	*  @brief Library Events
	*  @{
	*/
	NAMESPACE_ROUTING
		class Delegate {};
		class Event {};
	NAMESPACE_ROUTINGEND
	/*! @} */

	/*!
	*  \addtogroup Utility
	*  @{
	*  @brief Library Utilities Classes
	*/
	NAMESPACE_UTILITY 
		class ArrayTools {};
		class IntegerTools {};
		class MemoryPool {};
		class MemoryTools {};
		class ParallelTools {};
		class SystemTools {};
		class TimeStamp {};
	NAMESPACE_UTILITYEND
	/*! @} */

NAMESPACE_ROOTEND
/*! @} */

#endif
