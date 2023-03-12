// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2023 QSCS.ca
// This file is part of the CEX Cryptographic library.
// 
// This program is free software : you can redistribute it and/or modify
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
//
// 
// Written by John G. Underhill, January 21, 2015
// Updated December 9, 2016
// Updated April 20, 2016
// Contact: develop@qscs.ca

#ifndef CEX_CIPHERSTREAM_H
#define CEX_CIPHERSTREAM_H

#include "CexDomain.h"
#include "CryptoProcessingException.h"
#include "Event.h"
#include "IBlockCipher.h"
#include "IByteStream.h"
#include "ICipherMode.h"
#include "IPadding.h"
#include "ParallelOptions.h"
#include "SymmetricKeySize.h"
#include "SymmetricCiphers.h"

NAMESPACE_PROCESSING

using Enumeration::BlockCiphers;
using Exception::CryptoProcessingException;
using Enumeration::CipherModes;
using Routing::Event;
using Cipher::Block::IBlockCipher;
using IO::IByteStream;
using Cipher::Block::Mode::ICipherMode;
using Cipher::Block::Padding::IPadding;
using Cipher::ISymmetricKey;
using Enumeration::PaddingModes;
using Enumeration::SymmetricCiphers;
using Cipher::SymmetricKeySize;

/// <summary>
/// Used to wrap a streaming transformation.
/// <para>Wraps encryption stream functions in an easy to use interface.</para>
/// </summary> 
/// 
/// <example>
/// <description>Encrypting a file in-place:</description>
/// <code>
/// // initialize file stream; input must be set with Read and output must be ReadWrite access
/// FileStream* fIn = new FileStream("C://Tests//test.txt", FileStream::FileAccess::Read);
/// FileStream* fOut = new FileStream("C://Tests//test.txt", FileStream::FileAccess::ReadWrite);
/// Cipher::SymmetricKey kp(key, iv);
///
/// // instantiate the cipher with AES-CBC
/// CipherStream cs(Enumeration::BlockCiphers::AES, Enumeration::Digests::None, 14, Enumeration::CipherModes::CBC, Enumeration::PaddingModes::ESP);
/// // initialize the cipher for encryption
/// cs.Initialize(true, kp);
/// // write to file
/// cs.Write(fIn, fOut);
///
/// fIn.Close();
/// fOut.Close();
/// delete fIn;
/// delete fOut;
/// </code>
/// </example>
///
/// <example>
/// <description>Encrypting to a new file:</description>
/// <code>
/// // initialize file streams; input must be set with Read and output must be ReadWrite access
/// FileStream* fIn = new FileStream("C://Tests//test.txt", FileStream::FileAccess::Read);
/// FileStream* fOut = new FileStream("C://Tests//testenc.txt", FileStream::FileAccess::ReadWrite);
/// Cipher::SymmetricKey kp(key, iv);
///
/// // instantiate the cipher with AES-CTR
/// CipherStream cs(Enumeration::BlockCiphers::AES, Enumeration::Digests::None, 14, Enumeration::CipherModes::CTR);
/// // initialize the cipher for encryption
/// cs.Initialize(true, kp);
/// // write to file
/// cs.Write(fIn, fOut);
///
/// fIn.Close();
/// fOut.Close();
/// delete fIn;
/// delete fOut;
/// </code>
/// </example>
///
/// <remarks>
/// <description><B>Overview:</B></description>
/// <para>The CipherStream class is an easy to use wrapper that initializes and operates a symmetric cipher, automating many complex tasks down to just a couple of methods, 
/// in an extensible ease of use pattern. \n
/// Either a block cipher and mode, or a stream cipher can be initialized through the classes constructor, using either the cipher (and options) enumeration members, or a cipher instance. \n
/// The CipherStream class uses the IByteStream interface, and can encrypt either a uint8_t array using MemoryStream, or a file with FileStream. \n
/// This class supports parallel processing; if the cipher configuration supports parallelism (CTR/ICM, and CBC/CFB Decrypt), the IsParallel property will be set to true. \n
/// The IsParallel property can be overridden and set to false, disabling parallel processing. \n
/// If using the uint8_t array Write method, the output array should be at least ParallelBlockSize in length to enable parallel processing.</para>
///
/// <description><B>Implementation Notes:</B></description>
/// <list type="bullet">
/// <item><description>Uses any of the cipher mode wrapped block ciphers, or any of the implemented Stream Ciphers.</description></item>
/// <item><description>Implementation has a Progress counter that returns total sum of bytes processed during a Write call.</description></item>
/// <item><description>The Write methods can not be called until the Initialize(bool, ISymmetricKey) function has been called.</description></item>
/// <item><description>The Initialize function takes a boolean (Encrypt/Decrypt) flag and an ISymmetricKey, which can be either a SymmetricKey or SymmetricSecureKey container class.</description></item>
/// <item><description>If the system supports Parallel processing, IsParallel() is set to true; passing an output block of at least ParallelBlockSize to the Write function.</description></item>
/// <item><description>The ParallelThreadsMax() property is used as the thread count in the parallel loop; this must be an even number no greater than the number of processer cores on the system.</description></item>
/// <item><description>ParallelBlockSize() is calculated automatically based on the processor(s) L1 data cache size, this property can be user defined, and must be evenly divisible by ParallelMinimumSize().</description></item>
/// <item><description>The ParallelBlockSize(), IsParallel(), and ParallelThreadsMax() accessors, can be changed through the ParallelProfile() property</description></item>
/// <item><description>Parallel block calculation ex. <c>ParallelBlockSize = N - (N % .ParallelMinimumSize);</c></description></item>
/// </list>
/// </remarks>
class CipherStream
{
private:

	static const std::string CLASS_NAME;

	class CipherState;
	std::unique_ptr<CipherState> m_cipherState;
	std::unique_ptr<ICipherMode> m_cipherEngine;
	std::unique_ptr<IPadding> m_cipherPadding;
	std::vector<SymmetricKeySize> m_legalKeySizes;

public:

	/// <summary>
	/// The Progress Percent event
	/// </summary>
	Event<int32_t> ProgressPercent;

	//~~~Constructor~~~//

	/// <summary>
	/// Copy constructor: copy is restricted, this function has been deleted
	/// </summary>
	CipherStream(const CipherStream&) = delete;

	/// <summary>
	/// Copy operator: copy is restricted, this function has been deleted
	/// </summary>
	CipherStream& operator=(const CipherStream&) = delete;

	/// <summary>
	/// Initialize this class with block cipher enumeration parameters.
	/// <para>The default parameters are AES-256, using a parallel CTR mode.</para>
	/// </summary>
	/// 
	/// <param name="CipherType">The block cipher enumeration name</param>
	/// <param name="CipherModeType">The cipher mode enumeration name</param>
	/// <param name="PaddingType">The padding mode enumeration name</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if invalid parameters are passed</exception>
	CipherStream(BlockCiphers CipherType = BlockCiphers::AES, CipherModes CipherModeType = CipherModes::CTR, PaddingModes PaddingType = PaddingModes::None);

	/// <summary>
	/// Initialize the class with a block cipher mode and (optional) padding instances.
	/// <para>This constructor requires a non-null uninitialized ICipherMode instance.
	/// If the Padding parameter is null and the cipher requires padding, X9.23 padding will be used if required.</para>
	/// </summary>
	/// 
	/// <param name="Cipher">The block cipher wrapped in a cipher mode</param>
	/// <param name="Padding">The block cipher padding instance</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if a null cipher mode is used</exception>
	explicit CipherStream(ICipherMode* Cipher, IPadding* Padding = 0);

	/// <summary>
	/// Destroy this class
	/// </summary>
	~CipherStream();

	//~~~Accessors~~~//

	/// <summary>
	/// Read/Write: Automatic processor parallelization capable.
	/// <para>This value is true if the host supports parallelization.
	/// If the system and cipher configuration both support parallelization, it can be disabled by setting this value to false.</para>
	/// </summary>
	bool &IsParallel();

	/// <summary>
	/// Read Only: The supported key, nonce, and info sizes for the selected cipher configuration
	/// </summary>
	const std::vector<SymmetricKeySize> LegalKeySizes();

	/// <summary>
	/// Read Only: The stream ciphers implementation name
	/// </summary>
	const std::string Name();

	/// <summary>
	/// Read/Write: Parallel block size. Must be a multiple of <see cref="ParallelMinimumSize"/>.
	/// </summary>
	size_t ParallelBlockSize();

	/// <summary>
	/// Read/Write: Contains parallel settings and SIMD capability flags in a ParallelOptions structure.
	/// <para>The maximum number of threads allocated when using multi-threaded processing can be set with the ParallelMaxDegree(size_t) function.
	/// The ParallelBlockSize() property is auto-calculated, but can be changed; the value must be evenly divisible by the profiles ParallelMinimumSize() property.
	/// Note: The ParallelMaxDegree property can not be changed through this interface, use the ParallelMaxDegree(size_t) function to change the thread count 
	/// and reinitialize the state, or initialize the digest using a BlakeParams with the FanOut property set to the desired number of threads.</para>
	/// </summary>
	ParallelOptions &ParallelProfile();

	//~~~Public Functions~~~//

	/// <summary>
	/// Initialize the cipher with a key.
	/// <para>The ISymmetricKey can be either a SymmetricKey or a SymmetricSecureKey container.</para>
	/// </summary>
	/// 
	/// <param name="Encryption">The cipher is initialized for encryption</param>
	/// <param name="Parameters">The ISymmetricKey containing the cipher key and initialization vector</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if invalid key sizes are passed</exception>
	void Initialize(bool Encryption, ISymmetricKey &Parameters);

	/// <summary>
	/// Set the number of threads allocated when using multi-threaded tree hashing processing.
	/// <para>Thread count must be an even number, and not exceed the number of processor cores.
	/// Changing this value from the default (8 threads), will change the output hash value.</para>
	/// </summary>
	///
	/// <param name="Degree">The number of threads to allocate</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if invalid degree value is used</exception>
	void ParallelMaxDegree(size_t Degree);

	/// <summary>
	/// Process using file or memory streams.
	/// <para>When using FileStreams the InStream must be initialized as Read, and the OutStream initialized as ReadWrite.</para>
	/// </summary>
	/// 
	/// <param name="InStream">The input stream containing the data to transform</param>
	/// <param name="OutStream">The output stream that receives the transformed bytes</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if Write is called before Initialize, or the Input stream is empty</exception>
	void Write(IByteStream* InStream, IByteStream* OutStream);

	/// <summary>
	/// Process using uint8_t arrays.
	/// <para>The Input and Output arrays must be at least ParallelBlockSize to enable parallel processing.</para>
	/// </summary>
	/// 
	/// <param name="Input">The Input array</param>
	/// <param name="InOffset">The starting offset within the Input array</param>
	/// <param name="Output">The Output array</param>
	/// <param name="OutOffset">The starting offset within the Output array</param>
	/// 
	/// <exception cref="CryptoProcessingException">Thrown if Write is called before Initialize, or if array sizes are misaligned</exception>
	void Write(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);

private:

	void BlockTransform(const std::vector<uint8_t> &Input, size_t InOffset, std::vector<uint8_t> &Output, size_t OutOffset);
	void BlockTransform(IByteStream* InStream, IByteStream* OutStream);
	void CalculateProgress(size_t Length, size_t Processed);
	static ICipherMode* GetCipherMode(BlockCiphers CipherType, CipherModes CipherModeType);
	static IPadding* GetPaddingMode(PaddingModes PaddingType);
};

NAMESPACE_PROCESSINGEND
#endif
