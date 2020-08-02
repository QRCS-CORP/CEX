#include "SocketBase.h"

NAMESPACE_NETWORK

/// <summary>
/// The socket receiver class
/// </summary>
class SocketReceiver
{
private:

	socket_t &m_sourceSocket;
	bool m_eofReceived;

#if defined (CEX_WINDOWS_SOCKETS)
	WindowsHandle m_event;
	OVERLAPPED m_overlapped;
	bool m_resultPending;
	DWORD m_lastResult;
#else
	uint m_lastResult;
#endif

public:

	/// <summary>
	/// The socket receiver constructor
	/// </summary>
	SocketReceiver(socket_t &Source);

#if defined (CEX_BERKELY_SOCKETS)
	bool MustWaitToReceive()
	{
		return true;
	}
#else
	~SocketReceiver();
	bool MustWaitForResult()
	{
		return true;
	}
#endif

	/// <summary>
	/// Receive data into the buffer
	/// </summary>
	/// 
	/// <param name="Buffer">The data buffer</param>
	/// <param name="BufLen">The buffer length</param>
	bool Receive(byte* Buffer, size_t BufLen);

	/// <summary>
	/// Get the number of bytes received
	/// </summary>
	uint GetReceiveResult();

	/// <summary>
	/// Signals if end of file stream has been received
	/// </summary>
	bool EofReceived() const
	{
		return m_eofReceived;
	}

	/// <summary>
	/// Get the number of pending wait objects in thr queue
	/// </summary>
	uint GetMaxWaitObjectCount() const
	{
		return 1;
	}

	/// <summary>
	/// Get the wait objects on the call stack
	/// </summary>
	/// 
	/// <param name="Container">The wait object container</param>
	/// <param name="Stack">The call stack</param>
	void GetWaitObjects(WaitObjectContainer &Container, const CallStack &Stack);
};


NAMESPACE_NETWORKEND