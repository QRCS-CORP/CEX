#ifndef CEX_DOCUMENTATION_H
#define CEX_DOCUMENTATION_H

#error Documentation only!

#include "CexDomain.h"

// start doxygen main //
/*! \mainpage A programmers guide to the CEX++ Cryptographic library

\section intro_sec Welcome
Welcome to the CEX++ Cryptographic Library, version 1.1.0.0b (A10).
\brief
CEX is a library built for safety, speed, and maximum security.
This help package contains details on the cryptographic primitives used in the library, their uses, and code examples.

\section road_map Road Map
The current version is <B>v1.1.0.0b</B> (A10 version), which are the major, minor, patch, and release codes, and the update segment letter. \n
\brief

\author    John G. Underhill
\version   v1.1.0.0b
\date      March 12, 2023
\copyright AGPL version 3 license (GPLv3)

<B>Trajectory</B> \n \n

The current version is v1.1.0.0b (A10 version), which are the major, minor, patch, and release codes. \n \n

<B>Added tourrent Release v1.1.0.0b (version A10):</B> \n

\section intro_link Links
CEX++ on Github: https://github.com/Steppenwolfe65/CEX  \n
QSC on Github: https://github.com/QSC  \n
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
		class AsymmetricSecureKey {};
		class IAsymmetricKey {};

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
			*  \addtogroup Kyber
			*  @{
			*  @brief The McEliece Cipher Namespace
			*/
			NAMESPACE_KYBER
				class Kyber {};
			NAMESPACE_KYBEREND
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
			*  \addtogroup SphincsPlus
			*  @{
			*  @brief The SPHINCS+ asymmetric signature scheme Namespace
			*/
			NAMESPACE_SPHINCSPLUS
				class SphincsPlus {};
			NAMESPACE_SPHINCSPLUSEND
			/*! @} */

			/*!
			*  \addtogroup XMSS
			*  @{
			*  @brief The XMSS/MT asymmetric signature scheme Namespace
			*/
			NAMESPACE_XMSS
				class XMSS {};
			NAMESPACE_XMSSEND
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
				class ECB {};
				class HBA {};
				class IAeadMode {};
				class ICipherMode {};
				class ICM {};
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
			class ChaChaP20 {};
			class CSX512 {};
			class IStreamCipher {};
			class TSX256 {};
			class TSX512 {};
			class TSX1024 {};
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
		class SHA3256 {};
		class SHA3512 {};
		class SHA31024 {};
		class KeccakParams {};
		class SHA2 {};
		class SHA2256 {};
		class SHA2512 {};
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
		enum class AsymmetricCiphers {};
		enum class AsymmetricKeyTypes {};
		enum class AsymmetricParameters {};
		enum class AsymmetricPrimitives {};
		enum class AsymmetricSigners {};
		enum class Authenticators {};
		enum class BlockCiphers {};
		enum class CipherModes {};
		enum class CpuCores {};
		enum class Digests {};
		enum class DilithiumParameters {};
		enum class DrandEngines {};
		enum class Drbgs {};
		enum class Kdfs {};
		enum class KmacModes {};
		enum class Kms {};
		enum class KeySizes {};
		enum class KyberParameters {};
		enum class Macs {};
		enum class McElieceParameters {};
		enum class PaddingModes {};
		enum class Prngs {};
		enum class Providers {};
		enum class SHA2Digests {};
		enum class ShakeModes {};
		enum class SimdIntegers {};
		enum class SimdProfiles {};
		enum class SkeinUbiType {};
		enum class SphincsPlusParameters {};
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
		class CryptoSymmetricException {};
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
	*  \addtogroup KMS
	*  @{
	*  @brief Key Management Systems
	*/
	NAMESPACE_KMS
		class HKDS {};
	NAMESPACE_KMSEND
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
		class AES128 {};
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
		class CSR {};
		class HCR {};
		class IPrng {};
		class SecureRandom {};
	NAMESPACE_PRNGEND
	/*! @} */

	/*!
	*  \addtogroup Processing
	*  @{
	*  @brief Cryptographic Processing Namespace
	*/
	NAMESPACE_PROCESSING
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
	NAMESPACE_TOOLS 
		class ArrayTools {};
		class IntegerTools {};
		class MemoryPool {};
		class MemoryTools {};
		class ParallelTools {};
		class SystemTools {};
		class TimeStamp {};
	NAMESPACE_TOOLSEND
	/*! @} */

NAMESPACE_ROOTEND
/*! @} */

#endif
