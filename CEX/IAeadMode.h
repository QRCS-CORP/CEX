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

#ifndef CEX_IAEADMODE_H
#define CEX_IAEADMODE_H

#include "CexDomain.h"
#include "AeadModes.h"
#include "CryptoCipherModeException.h"
#include "IBlockCipher.h"
#include "ISymmetricKey.h"
#include "ParallelOptions.h"
#include "SecureVector.h"
#include "SymmetricKeySize.h"

NAMESPACE_MODE

using Enumeration::AeadModes;
using Exception::CryptoCipherModeException;
using Block::IBlockCipher;
using Cipher::ISymmetricKey;
using Cipher::SymmetricKeySize;

/// <summary>
/// An AEAD block-cipher mode virtual interface class.
/// <para>This class can be used to create functions that will accept any of the implemented AEAD modes instances as a parameter.</para>
/// </summary>
class IAeadMode
{
public:

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	IAeadMode(const IAeadMode&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	IAeadMode& operator=(const IAeadMode&) = delete;

	/// <summary>
	/// Initialize the IAeadMode virtual interface class
	/// </summary>
	IAeadMode() 
	{
	}

	/// <summary>
	/// Destructor: finalize this class
	/// </summary>
	virtual ~IAeadMode() noexcept
	{
	}

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Enable auto-incrementing of the input nonce, each time the Finalize method is called.
	/// <para>Treats the Nonce value loaded during Initialize as a monotonic counter; 
	/// incrementing the value by 1 and re-calculating the working set each time the cipher is finalized. 
	/// If set to false, requires a re-key after each finalization cycle.</para>
	/// </summary>
	virtual bool &AutoIncrement() = 0;

	/// <summary>
	/// Read Only: The Cipher Modes enumeration type name
	/// </summary>
	virtual const AeadModes Enumeral() = 0;

	/// <summary>
	/// Read Only: True if initialized for encryption, False for decryption
	/// </summary>
	virtual const bool IsEncryption() = 0;

	/// <summary>
	/// Read Only: The Block Cipher is ready to transform data
	/// </summary>
	virtual const bool IsInitialized() = 0;

	/// <summary>
	/// Read Only: Processor parallelization availability.
	/// <para>Indicates whether parallel processing is available with this mode.
	/// If parallel capable, input/output data arrays passed to the transform must be ParallelBlockSize in bytes to trigger parallelization.</para>
	/// </summary>
	virtual const bool IsParallel() = 0;

	/// <summary>
	/// Read Only: A vector of allowed cipher-mode input key byte-sizes
	/// </summary>
	virtual const std::vector<SymmetricKeySize> &LegalKeySizes() = 0;

	/// <summary>
	/// Read Only: The maximum legal MAC tag length in bytes
	/// </summary>
	virtual const size_t MaxTagSize() = 0;

	/// <summary>
	/// Read Only: The minimum legal MAC tag length in bytes
	/// </summary>
	virtual const size_t MinTagSize() = 0;

	/// <summary>
	/// Read Only: The cipher-modes formal class name
	/// </summary>
	virtual const std::string Name() = 0;

	/// <summary>
	/// Read Only: Parallel block size; the byte-size of the input/output data arrays passed to a transform that trigger parallel processing.
	/// <para>This value can be changed through the ParallelProfile class.</para>
	/// </summary>
	virtual const size_t ParallelBlockSize() = 0;

	/// <summary>
	/// Read/Write: Parallel and SIMD capability flags and sizes 
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree() property.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by ParallelMinimumSize().
	/// Changes to these values must be made before the <see cref="Initialize(SymmetricKey)"/> function is called.</para>
	/// </summary>
	virtual ParallelOptions &ParallelProfile() = 0;

	/// <summary>
	/// Read/Write: Persist a one-time associated data for the entire session.
	/// <para>Allows the use of a single SetAssociatedData() call to apply the MAC data to all segments.
	/// Finalize and Verify can be called multiple times, applying the initial associated data to each finalize cycle.</para>
	/// </summary>
	virtual bool &PreserveAD() = 0;

	/// <summary>
	/// Read Only: Returns the finalized MAC tag vector
	/// </summary>
	virtual const std::vector<byte> Tag() = 0;

	/// <summary>
	/// Copies the internal MAC tag to a secure-vector
	/// </summary>
	/// 
	/// <param name="Output">The secure-vector receiving the MAC code</param>
	virtual const void Tag(SecureVector<byte> &Output) = 0;

	//~~~Public Functions~~~//

	/// <summary>
	/// Calculate the MAC code (Tag) and copy it to the Output standard-vector.     
	/// <para>The output vector must be of sufficient length to receive the MAC code.
	/// This function finalizes the Encryption/Decryption cycle, all data must be processed before this function is called.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used, unless AutoIncrement is enabled.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output standard-vector that receives the authentication code</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">The number of MAC code bytes to write to the output vector.
	/// <para>Must be no greater than the MAC functions output size, and no less than the minimum Tag size.</para></param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized, or output vector is too small</exception>
	virtual void Finalize(std::vector<byte> &Output, size_t OutOffset, size_t Length) = 0;

	/// <summary>
	/// Calculate the MAC code (Tag) and copy it to the Output secure-vector.     
	/// <para>The output vector must be of sufficient length to receive the MAC code.
	/// This function finalizes the Encryption/Decryption cycle, all data must be processed before this function is called.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Output">The output secure-vector that receives the authentication code</param>
	/// <param name="OutOffset">The starting offset within the output vector</param>
	/// <param name="Length">The number of MAC code bytes to write to the output vector.
	/// <para>Must be no greater than the MAC functions output size, and no less than the minimum Tag size.</para></param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized, or output vector is too small</exception>
	virtual void Finalize(SecureVector<byte> &Output, size_t OutOffset, size_t Length) = 0;

	/// <summary>
	/// Initialize the Cipher instance
	/// </summary>
	///
	/// <param name="Encryption">True if cipher is used for encryption, false to decrypt</param>
	/// <param name="Parameters">The SymmetricKey containing key and vector</param>
	/// 
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid key or nonce is used</exception>
	virtual void Initialize(bool Encryption, ISymmetricKey &Parameters) = 0;

	/// <summary>
	/// Set the maximum number of threads allocated when using multi-threaded processing.
	/// <para>When set to zero, thread count is set automatically. If set to 1, sets IsParallel() to false and runs in sequential mode. 
	/// Thread count must be an even number, and not exceed the number of processor cores.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if an invalid degree setting is used</exception>
	virtual void ParallelMaxDegree(size_t Degree) = 0;

	/// <summary>
	/// Add additional data to the message authentication code generator.  
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and before any processing of plaintext or ciphertext input. 
	/// This function can only be called once per each initialization/finalization cycle.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input standard-vector of bytes to process</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if state has been processed</exception>
	virtual void SetAssociatedData(const std::vector<byte> &Input, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Add additional data to the message authentication code generator using a memory-locked vector.  
	/// <para>Must be called after Initialize(bool, ISymmetricKey), and before any processing of plaintext or ciphertext input. 
	/// This function can only be called once per each initialization/finalization cycle.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input standard-vector of bytes to process</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to process</param>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if state has been processed</exception>
	virtual void SetAssociatedData(const SecureVector<byte> &Input, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Transform a length of bytes with offset parameters. 
	/// <para>This method processes a specified length of bytes, utilizing offsets incremented by the caller.
	/// If IsParallel() is set to true, and the length is at least ParallelBlockSize(), the transform is run in parallel processing mode.
	/// To disable parallel processing, set the ParallelOptions().IsParallel() property to false.
	/// Initialize(bool, ISymmetricKey) must be called before this method can be used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input vector of bytes to transform</param>
	/// <param name="InOffset">Starting offset within the input vector</param>
	/// <param name="Output">The output vector of transformed bytes</param>
	/// <param name="OutOffset">Starting offset within the output vector</param>
	/// <param name="Length">The number of bytes to transform</param>
	virtual void Transform(const std::vector<byte> &Input, size_t InOffset, std::vector<byte> &Output, size_t OutOffset, size_t Length) = 0;

	/// <summary>
	/// Generate the internal MAC code and compare it with the tag contained in the Input standard-vector.   
	/// <para>This function finalizes the Decryption cycle and generates the MAC tag.
	/// The cipher must be set for Decryption and the cipher-text bytes fully processed before calling this function.
	/// Verify can be called in place of a Finalize(Output, Offset, Length) call, or after finalization.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input standard-vector containing the expected authentication code</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to compare.
	/// <para>Must be no greater than the MAC functions output size, and no less than the MinTagSize() size.</para></param>
	/// 
	/// <returns>Returns true if the authentication codes match</returns>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized for decryption</exception>
	virtual bool Verify(const std::vector<byte> &Input, size_t Offset, size_t Length) = 0;

	/// <summary>
	/// Generate the internal MAC code and compare it with the tag contained in the Input secure-vector.   
	/// <para>This function finalizes the Decryption cycle and generates the MAC tag.
	/// The cipher must be set for Decryption and the cipher-text bytes fully processed before calling this function.
	/// Verify can be called in place of a Finalize(Output, Offset, Length) call, or after finalization.
	/// Initialize(bool, ISymmetricKey) must be called before the cipher can be re-used.</para>
	/// </summary>
	/// 
	/// <param name="Input">The input secure-vector containing the expected authentication code</param>
	/// <param name="Offset">The starting offset within the input vector</param>
	/// <param name="Length">The number of bytes to compare.
	/// <para>Must be no greater than the MAC functions output size, and no less than the MinTagSize() size.</para></param>
	/// 
	/// <returns>Returns true if the authentication codes match</returns>
	///
	/// <exception cref="CryptoCipherModeException">Thrown if the cipher is not initialized for decryption</exception>
	virtual bool Verify(const SecureVector<byte> &Input, size_t Offset, size_t Length) = 0;
};

NAMESPACE_MODEEND
#endif
