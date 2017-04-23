#ifndef _CEX_DOCUMENTATION_H
#define _CEX_DOCUMENTATION_H

#error Documentation only!

#include "CexDomain.h"

// start doxygen main //
/*! \mainpage A programmers guide to the CEX++ Cryptographic library

\section intro_sec Welcome
Welcome to the CEX++ Cryptographic Library, version 1.0.0.2 (A2).
\brief
CEX is a library built for both speed and maximum security.
This help package contains details on the cryptographic primitives used in the library, their uses, and code examples.

\section road_map Road Map
The current version is <B>1.0.0.2</B> (A2 version), which are the major, minor, patch, and release codes. \n
\brief

<B>Release 1.0.0.3 (version A3):</B> \n
The RingLWE asymmetric cipher \n
The RLWE-SIG asymmetric signature scheme \n
The asymmetric cipher framework \n  \n

<B>Release 1.1.0.1</B> \n
RingLWE \n
RLWE-SIG \n
McEliece \n
GMSS \n
RSA-Sig \n \n

<B>Release 1.2.0.1</B> \n
Networking \n
TLS \n
STM-KEX \n
Android/iOS/Linux Compatability \n
DLL API \n

\author    John Underhill
\version   1.0.0.2
\date      April 23, 2017
\copyright GPL version 3 license (GPLv3)

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

	//NAMESPACE_ASYMMETRIC
	//NAMESPACE_ASYMMETRICEND
	//NAMESPACE_ASYENCRYPT
	//NAMESPACE_ASYENCRYPTEND
	//NAMESPACE_ASYKEX
	//NAMESPACE_ASYKEXEND
	//NAMESPACE_ASYSIGN
	//NAMESPACE_ASYSIGNEND

	/*!
	*  \addtogroup Cipher
	*  @{
	*  @brief Cryptographic Cipher Namespace
	*/
	NAMESPACE_CIPHER

		/*!
		*  \addtogroup Symmetric
		*  @{
		*  @brief Symmetric Cipher Namespace
		*/
		NAMESPACE_SYMMETRIC

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
			class THX {};

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
				class ISO7816 {};
				class PKCS7 {};
				class TBC {};
				class X923 {};
				class ZeroPad {};
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
			class IStreamCipher {};
			class ChaCha20 {};
			class Salsa20 {};
		NAMESPACE_STREAMEND
		/*! @} */

		NAMESPACE_SYMMETRICEND
		/*! @} */
	NAMESPACE_CIPHEREND
	/*! @} */
	/*!
	*  \addtogroup Common
	*  @brief Cipher Common Utilities
	*  @{
	*/
	NAMESPACE_COMMON
		class CipherDescription {};
		class CpuDetect {};
		class ParallelOptions {};
	NAMESPACE_COMMONEND
	/*! @} */

	/*!
	*  \addtogroup Digest
	*  @brief Cryptographic Hash Classes
	*  @{
	*/
	NAMESPACE_DIGEST
		class Blake512 {};
		class Blake256 {};
		class Blake2Params {};
		class IDigest {};
		class Keccak256 {};
		class Keccak512 {};
		class KeccakParams {};
		class SHA256 {};
		class SHA512 {};
		class SHA2Params {};
		class Skein256 {};
		class Skein512 {};
		class Skein1024 {};
		class SkeinParams {};
		class SkeinUbiTweak {};
		enum class SkeinUbiType {};
	NAMESPACE_DIGESTEND
	/*! @} */

	/*!
	*  \addtogroup Drbg
	*  @{
	*  @brief Deterministic Random Byte Generators
	*/
	NAMESPACE_DRBG
		class CMG {};
		class DCG {};
		class IDrbg {};
		class HMG {};
	NAMESPACE_DRBGEND
	/*! @} */

	/*!
	*  \addtogroup Enumeration
	*  @{
	*  @brief Cryptographic Enumerations
	*/
	NAMESPACE_ENUMERATION
		enum class AsymmetricEngines {};
		enum class BlockCiphers {};
		enum class BlockSizes {};
		enum class CipherModes {};
		enum class Digests {};
		enum class Drbgs {};
		enum class IVSizes {};
		enum class Kdfs {};
		enum class KeySizes {};
		enum class Macs {};
		enum class PaddingModes {};
		enum class Prngs {};
		enum class RoundCounts {};
		enum class Providers {};
		enum class SimdProfiles {};
		enum class StreamCiphers {};
		enum class SymmetricEngines {};
	NAMESPACE_ENUMERATIONEND
	/*! @} */

	/*!
	*  \addtogroup Exception
	*  @{
	*  @brief Cryptographic Exceptions
	*/
	NAMESPACE_EXCEPTION
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
		class BlockCipherFromName {};
		class CipherFromDescription {};
		class CipherModeFromName {};
		class DigestFromName {};
		class MacFromDescription {};
		class PaddingFromName {};
		class PrngFromName {};
		class ProviderFromName {};
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
	NAMESPACE_KDFEND
	/*! @} */

	/*!
	*  \addtogroup Key
	*  @{
	*  @brief Cipher Keys
	*/
	NAMESPACE_KEY
		/*!
		*  \addtogroup SymmetricKey
		*  @{
		*  @brief Symmetric Key containers and generator
		*/
		NAMESPACE_KEYSYMMETRIC
		class ISymmetricKey {};
		class SymmetricKeyGenerator {};
		class SymmetricKey {};
		class SymmetricKeySize {};
		class SymmetricSecureKey {};
		NAMESPACE_KEYSYMMETRICEND
		/*! @} */
	NAMESPACE_KEYEND
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
		class UInt128 {};
		class UInt256 {};
		class UInt512 {};
		class ULong256 {};
	NAMESPACE_NUMERICEND
	/*! @} */

	/*!
	*  \addtogroup Prng
	*  @{
	*  @brief Pseudo Random Number Generators
	*/
	NAMESPACE_PRNG
		class CMR {};
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
		class ArrayUtils {};
		class IntUtils {};
		class MemUtils {};
		class ParallelUtils {};
		class SysUtils {};
	NAMESPACE_UTILITYEND
	/*! @} */

NAMESPACE_ROOTEND
/*! @} */
#endif
