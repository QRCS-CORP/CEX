#ifndef CEX_PACKETBUFFER_H
#define CEX_PACKETBUFFER_H

#include "CexDomain.h"
#include "MemoryStream.h"

NAMESPACE_NETWORK

using IO::MemoryStream;

/// <summary>
/// A class that contains a searchable list of packet streams
/// </summary>
class PacketBuffer
{
public:

	/// <summary>
	/// Get: Return the number of packet streams in the buffer
	/// </summary>
	size_t Count()
	{
		return 0;
	}

	/// <summary>
	/// Get/Set: The size of the buffer queue
	/// </summary>
	/// 
	/// <exception cref="CryptoNetworkingException">Thrown if the queue depth is less than 1</exception>
	int Depth()
	{
		return 0;
	}

	/// <summary>
	/// Initialize this class
	/// </summary>
	/// 
	/// <param name="QueueDepth">The maximum queue depth</param>
	PacketBuffer(size_t QueueDepth)
	{
	}

	PacketBuffer()
	{
	}

	/// <summary>
	/// Finalize objects
	/// </summary>
	~PacketBuffer()
	{
	}

	/// <summary>
	/// Clear the buffer, disposing of each element
	/// </summary>
	/// 
	/// <exception cref="CryptoNetworkingException">Thrown if the clearing the queue produced an error</exception>
	void Clear()
	{
		/*try
		{
			if (m_pktBuffer != null)
			{
				List<MemoryStream> vals = new List<MemoryStream>(m_pktBuffer.Values);

				foreach(MemoryStream pkt in vals)
				{
					if (pkt != null)
						pkt.Dispose();
				}

				m_pktBuffer.Clear();
			}
		}
		catch
		{
			throw;
		}*/
	}

	/// <summary>
	/// Remove a packet stream from the buffer
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// 
	/// <returns>Returns true if the packet was destroyed, otherwise false</returns>
	bool Destroy(size_t Sequence)
	{
		/*try
		{
			MemoryStream pkt = Peek(Sequence);

			if (Remove(Sequence))
			{
				if (pkt != null)
					pkt.Dispose();

				return true;
			}
		}
		catch
		{
			throw;
		}

		return false;*/
	}

	/// <summary>
	/// Check if the buffer contains a packet with this key
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// 
	/// <returns>Returns <c>true</c> if the key exists, otherwise <c>false</c></returns>
	bool Exists(size_t Sequence)
	{
		//return m_pktBuffer == null ? false : m_pktBuffer.ContainsKey(Sequence);
		return false;
	}

	/// <summary>
	/// Get the key with the lowest sequence number
	/// </summary>
	/// 
	/// <returns>The lowest key, or -1 for empty</returns>
	size_t GetHighKey()
	{
		/*long size_t = -1;

		lock(m_threadLock)
		{
			List<long> keys = new List<long>(m_pktBuffer.Keys);

			foreach(long key in keys)
			{
				if (key > lstSeq)
					lstSeq = key;
			}
		}

		return lstSeq;*/
	}

	/// <summary>
	/// Get the key with the highest sequence number
	/// </summary>
	/// 
	/// <returns>The highest key, or -1 for empty</returns>
	size_t GetLowKey()
	{
		/*long lstSeq = long.MaxValue;

		lock(m_threadLock)
		{
			List<long> keys = new List<long>(m_pktBuffer.Keys);

			foreach(long key in keys)
			{
				if (key < lstSeq)
					lstSeq = key;
			}
		}

		if (lstSeq == long.MaxValue)
			return -1;
		else
			return lstSeq;*/
	}

	/// <summary>
	/// Return the packet stream with the specified sequence number
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// 
	/// <returns>Returns the packet stream, or if not found, an empty MemoryStream object</returns>
	MemoryStream Peek(size_t Sequence)
	{
		/*MemoryStream pkt = null;

		if (Exists(Sequence))
		{
			m_pktBuffer.TryGetValue(Sequence, out pkt);

			if (pkt.Position != 0)
				pkt.Seek(0, SeekOrigin.Begin);
		}

		return pkt;*/
	}

	/// <summary>
	/// Return the packet stream with the specified sequence number and removes it from the buffer
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// 
	/// <returns>Returns the packet stream, or if not found, an empty MemoryStream object</returns>
	MemoryStream Pop(size_t Sequence)
	{
		/*MemoryStream pkt = new MemoryStream();

		if (Exists(Sequence))
		{
			if (m_pktBuffer.TryGetValue(Sequence, out pkt))
				Remove(Sequence);

			if (pkt.Position != 0)
				pkt.Seek(0, SeekOrigin.Begin);
		}

		return pkt;*/
	}

	/// <summary>
	/// Returns the position of a packet within the buffer, <c>-1</c> is returned if the sequence number can not be found
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// 
	/// <returns>Returns the index of the packet within the buffer, or if not found, returns the value <c>-1</c></returns>
	int Position(size_t Sequence)
	{
		/*if (!Exists(Sequence))
			return -1;

		int count = 0;

		lock(m_threadLock)
		{
			List<long> keys = new List<long>(m_pktBuffer.Keys);
			foreach(var key in keys)
			{
				if (Sequence.Equals(key))
					return count;

				count++;
			}
		}

		return -1;*/
	}

	/// <summary>
	/// Add a packet stream to the buffer.
	/// <para>If a packet is added and the buffer size exceeds the Queue Depth, 
	/// the packet with the lowest sequence number is removed</para>
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// <param name="Packet">The packet stream</param>
	void Push(size_t Sequence, MemoryStream &Packet)
	{
		/*if (m_pktBuffer == null)
			return;

		if (Packet.Position != 0)
			Packet.Seek(0, SeekOrigin.Begin);

		// remove first in queue
		if (m_pktBuffer.Count > m_queueDepth)
		{
			long fstSeq = GetLowKey();

			if (fstSeq > -1)
				Remove(fstSeq);
		}

		// possible resend
		if (Exists(Sequence))
			Remove(Sequence);

		m_pktBuffer.TryAdd(Sequence, Packet);*/
	}

	/// <summary>
	/// Remove a packet stream from the buffer
	/// </summary>
	/// 
	/// <param name="Sequence">The packet sequence number</param>
	/// 
	/// <returns>Returns true if the packet was removed, otherwise false</returns>
	bool Remove(size_t Sequence)
	{
		/*if (m_pktBuffer == null)
			return false;
		else if (m_pktBuffer.Count < 1)
			return false;

		MemoryStream pkt = null;
		m_pktBuffer.TryRemove(Sequence, out pkt);

		if (pkt != null)
			return true;*/

		return false;
	}
};

NAMESPACE_NETWORKEND
#endif
