// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2019 vtdev.com
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and / or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

#ifndef CEX_ISTREAMCIPHER_H
#define CEX_ISTREAMCIPHER_H

#include "CexDomain.h"
#include "CryptoAuthenticationFailure.h"
#include "CryptoSymmetricException.h"
#include "IMac.h"
#include "ISymmetricKey.h"
#include "ParallelOptions.h"
#include "ParallelTools.h"
#include "SecureVector.h"
#include "StreamAuthenticators.h"
#include "StreamCiphers.h"
#include "SymmetricKey.h"
#include "SymmetricKeySize.h"

NAMESPACE_STREAM

using Exception::CryptoAuthenticationFailure;
using Exception::CryptoSymmetricException;
using Enumeration::ErrorCodes;
using Mac::IMac;
using Cipher::ISymmetricKey;
using Enumeration::StreamAuthenticators;
using Enumeration::StreamCiphers;
using Cipher::SymmetricKey;
using Cipher::SymmetricKeySize;

/// <summary>
/// The stream-cipher virtual interface class.
/// <para>This class can be used to create functions that will accept any of the implemented stream-cipher instances as a parameter.</para>
/// </summary>
class IStreamCipher
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IStreamCipher(const IStreamCipher&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IStreamCipher& operator=(const IStreamCipher&) = delete;

	/// <summary>
	/// Constructor: Instantiate this class
	/// </summary>
	IStreamCipher() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IStreamCipher() 
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read Only: The stream ciphers type name
	/// </summary>
	virtual const StreamCiphers Enumeral() = 0;

	/// <summary>
	/// Read Only: Cipher has authentication enabled
	/// </summary>
	virtual const bool IsAuthenticator() = 0;

	/// <summary>
	/// Read Only: The cipher has been initialized for encryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Read Only: Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() = 0;

	/// <summary>
	/// Read Only: A vector of SymmetricKeySize containers, containing legal cipher input-key sizes
	/// </summary>
	virtual const std::vector<SymmetricKeySize> &LegalKeySizes() = 0;

	/// <summary>
	/// Read Only: The stream ciphers formal implementation name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class, but must be a multiple of the ParallelMinimumSize().</para>
	/// </summary>
	virtual const size_t ParallelBlockSize() = 0;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the Initialize(bool, ISymmetricKey) function is called.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() = 0;

	/// <summary>
	/// Read Only: The current MAC tag value
	/// </summary>
	virtual const std::vector<byte> Tag() = 0;

	/// <summary>
	/// Copies the internal MAC tag to a secure-vector
	/// </summary>
	/// 
	/// <param name="Output">The secure-vector receiving the MAC code</param>
	virtual const void Tag(SecureVector<byte> &Output) = 0;

	/// <summary>
	/// Read Only: The legal MAC tag length in bytes
	/// </summary>
	virtual const size_t TagSize() = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the cipher with an ISymmetricKey key container.
	/// <para>If authentication is enabled, setting the Encryption parameter to false will decrypt and authenticate a ciphertext stream.
	/// Authentication on a decrypted stream is performed automatically; failure will throw a CryptoAuthenticationFailure exception.
	/// If encryption and authentication are set to true, the MAC code is appended to the cipher-text array after each transform call.</para>
	/// </summary>
	/// 
	/// <param name="Parameters">Cipher key container. The LegalKeySizes property contains valid sizes</param>
	/// <param name="Encryption">Using Encryption or Decryption mode</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if a null or invalid key is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &Parameters) = 0;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor virtual cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

	/// <summary>
	/// Add additional data to the message authentication code generator.  
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and can then be called before or after a stream segment has been processed.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to process</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoSymmetricException">Thrown if state has been processed</exception>
	virtual void SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Encrypt/Decrypt a vector of bytes with offset and length parameters.
	/// <para>Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to transform</param>
	/// <param name="InOffset">The starting offset within the input vector</param>
	/// <param name="Output">The output vector of transformed bytes</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">The byte length of data to process</param>
	virtual void Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length) = 0;
};

NAMESPACE_STREAMEND
#endif
