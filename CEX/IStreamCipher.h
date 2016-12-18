#ifndef _CEX_IStreamCipher_H
#define _CEX_IStreamCipher_H

#include "CexDomain.h"
#include "CryptoSymmetricCipherException.h"
#include "ISymmetricKey.h"
#include "ParallelUtils.h"
#include "StreamCiphers.h"
#include "SymmetricKeySize.h"

NAMESPACE_STREAM

using Exception::CryptoSymmetricCipherException;
using Key::Symmetric::ISymmetricKey;
using Enumeration::StreamCiphers;
using Key::Symmetric::SymmetricKeySize;

/// <summary>
/// Stream Cipher Interface
/// </summary>
class IStreamCipher
{

public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Instantiate this class
	/// </summary>
	IStreamCipher() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IStreamCipher() {}

	//~~~Properties~~~//

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide. 
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Get/Set: The salt value in the initialization parameters (Tau-Sigma).
	/// <para>This value can also be set with the Info parameter of an ISymmetricKey member, or use the default.
	/// Changing this code will create a unique distribution of the cipher.
	/// Code must be non-zero, 16 bytes in length, and sufficiently asymmetric.
	/// If the Info parameter of an ISymmetricKey is non-zero, it will overwrite the distribution code.</para>
	/// </summary>
	virtual std::vector<byte> &DistributionCode() = 0;

	/// <summary>
	/// Get: The stream ciphers type name
	/// </summary>
	virtual const StreamCiphers Enumeral() = 0;

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX2() = 0;

	/// <summary>
	/// Get: Returns True if the cipher supports SIMD intrinsics
	/// </summary>
	virtual const bool HasSSE() = 0;

	/// <summary>
	/// Get: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Get/Set: Automatic processor parallelization
	/// </summary>
	virtual bool &IsParallel() = 0;

	/// <summary>
	/// Get: Initialization vector size
	/// </summary>
	virtual const size_t IvSize() = 0;

	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide. 
	/// Value set in class constructor.</para>
	/// </summary>
	virtual std::vector<SymmetricKeySize> LegalKeySizes() const = 0;

	/// <summary>
	/// Get: Available transformation round assignments
	/// </summary>
	virtual const std::vector<size_t> LegalRounds() = 0;

	/// <summary>
	/// Get: The stream ciphers class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Get/Set: Parallel block size; must be set before Initialize()
	/// </summary>
	virtual size_t &ParallelBlockSize() = 0;

	/// <summary>
	/// Get: Maximum input size with parallel processing
	/// </summary>
	virtual const size_t ParallelMaximumSize() = 0;

	/// <summary>
	/// Get: The smallest parallel block size. Parallel blocks must be a multiple of this size.
	/// </summary>
	virtual const size_t ParallelMinimumSize() = 0;

	/// <summary>
	/// Get: The maximum number of threads allocated when using multi-threaded processing
	/// </summary>
	virtual size_t &ParallelThreadsMax() = 0;

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	virtual const size_t ProcessorCount() = 0;

	/// <summary>
	/// Get: Number of rounds
	/// </summary>
	virtual const size_t Rounds() = 0;

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Initialize the cipher
	/// </summary>
	/// 
	/// <param name="KeyParam">Cipher key container. The LegalKeySizes property contains valid sizes</param>
	virtual void Initialize(ISymmetricKey &KeyParam) = 0;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="Output">The output array of transformed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset parameters.
	/// <para><see cref="Initialize(SymmetricKey)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset and length parameters.
	/// <para><see cref="Initialize(SymmetricKey)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input array of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input array</param>
	/// <param name="Output">The output array of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) = 0;
};

NAMESPACE_STREAMEND
#endif
