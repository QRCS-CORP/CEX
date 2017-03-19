// The GPL version 3 License (GPLv3)
// 
// Copyright (c) 2017 vtdev.com
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
// along with this program.If not, see <http://www.gnu.org/licenses/>.

#ifndef _CEX_BLAKE2PARAMS_H
#define _CEX_BLAKE2PARAMS_H

#include "CexDomain.h"
#include "CryptoDigestException.h"

NAMESPACE_DIGEST

	/// <summary>
	/// The Blake2 parameters structure
	/// </summary> 
	struct BlakeParams
	{
	private:
		static const size_t HDR_SIZE = 36;

		byte m_dgtLen;
		byte m_keyLen;
		byte m_fanOut;
		byte m_maxDepth;
		uint m_leafLength;
		ulong m_nodeOffset;
		byte m_nodeDepth;
		byte m_innerLen;
		byte m_threadDepth;
		byte m_reserved2;
		ulong m_reserved3;
		ulong m_reserved4;

	public:
		/// <summary>
		/// Get/Set: Digest byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s
		/// </summary>
		byte &DigestLength() { return m_dgtLen; }

		/// <summary>
		/// Get/Set: Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)
		/// </summary>
		byte &KeyLength() { return m_keyLen; }

		/// <summary>
		/// Get/Set: Fanout (1 byte): an integer in [0, 255] (set to 0 if unlimited, and to 1 only in sequential mode)
		/// </summary>
		byte &FanOut() { return m_fanOut; }

		/// <summary>
		/// Get/Set: Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)
		/// </summary>
		byte &MaxDepth() { return m_maxDepth; }

		/// <summary>
		/// Get/Set: Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)
		/// </summary>
		uint &LeafLength() { return m_leafLength; }

		/// <summary>
		/// Get/Set: Node offset (8 or 6 bytes): an integer in [0, 264 −1] for BLAKE2b, and in [0, 248 −1] for BLAKE2s(set to 0 for the first, leftmost, leaf, or in sequential mode)
		/// </summary>
		ulong &NodeOffset() { return m_nodeOffset; }

		/// <summary>
		/// Get/Set: Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)
		/// </summary>
		byte &NodeDepth() { return m_nodeDepth; }

		/// <summary>
		/// Get/Set: Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)
		/// </summary>
		byte &InnerLength() { return m_innerLen; }

		/// <summary>
		/// Get/Set: The desired number of threads used to process the message (default is 4 for Blake2-BP, or 8 for Blake2-SP)
		/// </summary>
		byte &ParallelDegree() { return m_threadDepth; }

		/// <summary>
		/// Get/Set: The second reserved byte
		/// </summary>
		byte &Reserved2() { return m_reserved2; }

		/// <summary>
		/// Get/Set: The third reserved ulong
		/// </summary>
		ulong &Reserved3() { return m_reserved3; }

		/// <summary>
		/// Get/Set: The fourth reserved ulong
		/// </summary>
		ulong &Reserved4() { return m_reserved4; }


		/// <summary>
		/// Initialize the default structure.
		/// <para>Default settings are linear mode (Blake2-B).</para>
		/// </summary>
		explicit BlakeParams()
			:
			m_dgtLen(64),
			m_keyLen(0),
			m_fanOut(1),
			m_maxDepth(1),
			m_leafLength(0),
			m_nodeOffset(0),
			m_nodeDepth(0),
			m_innerLen(0),
			m_threadDepth(8),
			m_reserved2(0),
			m_reserved3(0),
			m_reserved4(0)
		{
		}

		/// <summary>
		/// Initialize the MessageHeader structure using a serialized byte array
		/// </summary>
		explicit BlakeParams(std::vector<byte> TreeArray)
			:
			m_dgtLen(0),
			m_keyLen(0),
			m_fanOut(0),
			m_maxDepth(0),
			m_leafLength(0),
			m_nodeOffset(0),
			m_nodeDepth(0),
			m_innerLen(0),
			m_threadDepth(0),
			m_reserved2(0),
			m_reserved3(0),
			m_reserved4(0)
		{
			if (TreeArray.size() < HDR_SIZE)
				throw Exception::CryptoDigestException("BlakeParams:Ctor", "The TreeArray buffer is too short!");

			memcpy(&m_dgtLen, &TreeArray[0], 1);
			memcpy(&m_keyLen, &TreeArray[1], 1);
			memcpy(&m_fanOut, &TreeArray[2], 1);
			memcpy(&m_maxDepth, &TreeArray[3], 1);
			memcpy(&m_leafLength, &TreeArray[4], 4);
			memcpy(&m_nodeOffset, &TreeArray[8], 8);
			memcpy(&m_nodeDepth, &TreeArray[16], 1);
			memcpy(&m_innerLen, &TreeArray[17], 1);
			memcpy(&m_threadDepth, &TreeArray[18], 1);
			memcpy(&m_reserved2, &TreeArray[19], 1);
			memcpy(&m_reserved3, &TreeArray[20], 8);
			memcpy(&m_reserved4, &TreeArray[28], 8);
		}

		/// <summary>
		/// Initialize this structure with parameters
		/// </summary>
		/// 
		/// <param name="DigestLength">Digest byte length (1 byte): an integer in [1, 64] for BLAKE2b, in [1, 32] for BLAKE2s</param>
		/// <param name="KeyLength">Key byte length (1 byte): an integer in [0, 64] for BLAKE2b, in [0, 32] for BLAKE2s (set to 0 if no key is used)</param>
		/// <param name="FanOut">Fanout (1 byte): an integer in [0, 255] (set to 0 if unlimited, and to 1 only in sequential mode)</param>
		/// <param name="MaxDepth">Maximal depth (1 byte): an integer in [1, 255] (set to 255 if unlimited, and to 1 only in sequential mode)</param>
		/// <param name="LeafLength">Leaf maximal byte length (4 bytes): an integer in [0, 232 − 1], that is, up to 4 GiB (set to 0 if unlimited, or in sequential mode)</param>
		/// <param name="NodeOffset">Node offset (8 or 6 bytes): an integer in [0, 264 −1] for BLAKE2b, and in [0, 248 −1] for BLAKE2s(set to 0 for the first, leftmost, leaf, or in sequential mode)</param>
		/// <param name="NodeDepth">Node depth (1 byte): an integer in [0, 255] (set to 0 for the leaves, or in sequential mode)</param>
		/// <param name="InnerLength">Inner hash byte length (1 byte): an integer in [0, 64] for BLAKE2b, and in [0, 32] for BLAKE2s(set to 0 in sequential mode)</param>
		/// <param name="ParallelDegree">The number of threads used in parallel mode, the default is 4 for Blake2bp, and 8 for Blake2sp</param>
		explicit BlakeParams(byte DigestLength, byte KeyLength, byte FanOut, byte MaxDepth, uint LeafLength, ulong NodeOffset, byte NodeDepth, byte InnerLength, byte ParallelDegree)
			:
			m_dgtLen(DigestLength),
			m_keyLen(KeyLength),
			m_fanOut(FanOut),
			m_maxDepth(MaxDepth),
			m_leafLength(LeafLength),
			m_nodeOffset(NodeOffset),
			m_nodeDepth(NodeDepth),
			m_innerLen(InnerLength),
			m_threadDepth(ParallelDegree),
			m_reserved2(0),
			m_reserved3(0),
			m_reserved4(0)
		{
		}

		/// <summary>
		/// Create a clone of this structure
		/// </summary>
		BlakeParams Clone()
		{
			BlakeParams result(DigestLength(), KeyLength(), FanOut(), MaxDepth(), LeafLength(), NodeOffset(), NodeDepth(), InnerLength(), ParallelDegree());
			return result;
		}

		/// <summary>
		/// Create a deep copy of this structure.
		/// <para>Caller must delete this object.</para>
		/// </summary>
		/// 
		/// <returns>A pointer to a BlakeParams instance</returns>
		BlakeParams* DeepCopy()
		{
			return new BlakeParams(DigestLength(), KeyLength(), FanOut(), MaxDepth(), LeafLength(), NodeOffset(), NodeDepth(), InnerLength(), ParallelDegree());
		}

		/// <summary>
		/// Compare this object instance with another
		/// </summary>
		/// 
		/// <param name="Obj">Object to compare</param>
		/// 
		/// <returns>True if equal, otherwise false</returns>
		bool Equals(BlakeParams &Obj)
		{
			if (this->GetHashCode() != Obj.GetHashCode())
				return false;

			return true;
		}

		/// <summary>
		/// Get the hash code for this object
		/// </summary>
		/// 
		/// <returns>Hash code</returns>
		int GetHashCode()
		{
			int result = 31 * m_dgtLen;

			result += 31 * m_keyLen;
			result += 31 * m_fanOut;
			result += 31 * m_maxDepth;
			result += 31 * m_leafLength;
			result += 31 * (int)m_nodeOffset;
			result += 31 * m_nodeDepth;
			result += 31 * m_innerLen;
			result += 31 * m_threadDepth;
			result += 31 * m_reserved2;
			result += 31 * (int)m_reserved3;
			result += 31 * (int)m_reserved4;

			return result;
		}

		/// <summary>
		/// Get the header size in bytes
		/// </summary>
		/// 
		/// <returns>Header size</returns>
		static int GetHeaderSize()
		{
			return HDR_SIZE;
		}

		/// <summary>
		/// Set all struct members to defaults
		/// </summary>
		void Reset()
		{
			m_dgtLen = 0;
			m_keyLen = 0;
			m_fanOut = 0;
			m_maxDepth = 0;
			m_leafLength = 0;
			m_nodeOffset = 0;
			m_nodeDepth = 0;
			m_innerLen = 0;
			m_threadDepth = 0;
			m_reserved2 = 0;
			m_reserved3 = 0;
			m_reserved4 = 0;
		}

		/// <summary>
		/// Convert the BlakeParams structure serialized to a byte array
		/// </summary>
		/// 
		/// <returns>The byte array containing the BlakeParams</returns>
		std::vector<byte> ToBytes()
		{
			std::vector<byte> trs(HDR_SIZE, 0);

			memcpy(&trs[0], &m_dgtLen, 1);
			memcpy(&trs[1], &m_keyLen, 1);
			memcpy(&trs[2], &m_fanOut, 1);
			memcpy(&trs[3], &m_maxDepth, 1);
			memcpy(&trs[4], &m_leafLength, 4);
			memcpy(&trs[8], &m_nodeOffset, 8);
			memcpy(&trs[16], &m_nodeDepth, 1);
			memcpy(&trs[17], &m_innerLen, 1);
			memcpy(&trs[18], &m_threadDepth, 1);
			memcpy(&trs[19], &m_reserved2, 1);
			memcpy(&trs[20], &m_reserved3, 8);
			memcpy(&trs[28], &m_reserved4, 8);

			return trs;
		}
	};

NAMESPACE_DIGESTEND
#endif