#ifndef _CEXENGINE_IStreamCipher_H
#define _CEXENGINE_IStreamCipher_H

#include "Common.h"
#include "KeyParams.h"
#include "ParallelUtils.h"
#include "StreamCiphers.h"
#if defined(CPPEXCEPTIONS_ENABLED)
#	include "CryptoSymmetricCipherException.h"
#endif

NAMESPACE_STREAM

using CEX::Common::KeyParams;
using CEX::Enumeration::StreamCiphers;
#if defined(CPPEXCEPTIONS_ENABLED)
	using CEX::Exception::CryptoSymmetricCipherException;
#endif

/// <summary>
/// Stream Cipher Interface
/// </summary>
class IStreamCipher
{

public:
	//~~~Constructor~~~//

	/// <summary>
	/// CTor: Initialize this class
	/// </summary>
	IStreamCipher() {}

	/// <summary>
	/// Destructor
	/// </summary>
	virtual ~IStreamCipher() {}


	/// <summary>
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide. 
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const size_t BlockSize() = 0;

	/// <summary>
	/// Get: The stream ciphers type name
	/// </summary>
	virtual const StreamCiphers Enumeral() = 0;

	/// <summary>
	/// Get: Returns True if the cipher supports AVX intrinsics
	/// </summary>
	virtual const bool HasAVX() = 0;

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
	/// Get: Unit block size of internal cipher in bytes.
	/// <para>Block size must be 16 or 32 bytes wide. 
	/// Value set in class constructor.</para>
	/// </summary>
	virtual const std::vector<size_t> &LegalKeySizes() = 0;

	/// <summary>
	/// Get: Available diffusion round assignments
	/// </summary>
	virtual const std::vector<size_t> &LegalRounds() = 0;

	/// <summary>
	/// Get: Cipher name
	/// </summary>
	virtual const char *Name() = 0;

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
	virtual const size_t ParallelThreadsMax() = 0;

	/// <remarks>
	/// Get: Processor count
	/// </remarks>
	virtual const size_t ProcessorCount() = 0;

	/// <summary>
	/// Get: Number of rounds
	/// </summary>
	virtual const size_t Rounds() = 0;

	/// <summary>
	/// Get: Initialization vector size
	/// </summary>
	virtual const size_t VectorSize() = 0;

	//~~~Public Methods~~~//

	/// <summary>
	/// Release all resources associated with the object
	/// </summary>
	virtual void Destroy() = 0;

	/// <summary>
	/// Initialize the Cipher
	/// </summary>
	/// 
	/// <param name="KeyParam">Cipher key container. The LegalKeySizes property contains valid sizes</param>
	virtual void Initialize(const KeyParams &KeyParam) = 0;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The desired number of threads</param>
	///
	/// <exception cref="CEX::Exception::CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes
	/// </summary>
	/// 
	/// <param name="Input">Input bytes, plain text for encryption, cipher text for decryption</param>
	/// <param name="Output">Output bytes, array of at least equal size of input that receives processed bytes</param>
	virtual void Transform(const std::vector<byte> &Input, std::vector<byte> &Output) = 0;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset parameters.
	/// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset) = 0;

	/// <summary>
	/// Encrypt/Decrypt an array of bytes with offset and length parameters.
	/// <para><see cref="Initialize(KeyParams)"/> must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">Input bytes to Transform</param>
	/// <param name="InOffset">Offset in the Input array</param>
	/// <param name="Output">Output product of Transform</param>
	/// <param name="OutOffset">Offset in the Output array</param>
	/// <param name="Length">Length of data to process</param>
	virtual void Transform(const std::vector<byte> &Input, const size_t InOffset, std::vector<byte> &Output, const size_t OutOffset, const size_t Length) = 0;
};

NAMESPACE_STREAMEND
#endif
