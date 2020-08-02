#include "SocketBase.h"

NAMESPACE_NETWORK


/// <summary>
/// The socket sender class
/// </summary>
class SocketSender
{
private:

	socket_t m_sourceSocket;
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
	/// The socket sender constructor
	/// </summary>
	SocketSender(socket_t &Source);

#if defined (CEX_BERKELY_SOCKETS)
	/// <summary>
	/// The must wait status
	/// </summary>
	bool MustWaitToSend()
	{
		return true;
	}
#else

	/// <summary>
	/// The socket sender destructor
	/// </summary>
	~SocketSender();

	/// <summary>
	/// The must wait for result status
	/// </summary>
	bool MustWaitForResult()
	{
		return true;
	}

	/// <summary>
	/// The must wait for end of file status
	/// </summary>
	bool MustWaitForEof()
	{
		return true;
	}

	/// <summary>
	/// The end of file sent status
	/// </summary>
	bool EofSent();
#endif

	/// <summary>
	/// Send a buffer on the socket
	/// </summary>
	/// 
	/// <param name="Buffer">The send buffer</param>
	/// <param name="BufLen">The send buffer length</param>
	void Send(const byte* Buffer, size_t BufLen);

	/// <summary>
	/// The send operation result
	/// </summary>
	uint GetSendResult();

	/// <summary>
	/// Send the eof file message
	/// </summary>
	void SendEof();

	/// <summary>
	/// Get the maximum wait object count
	/// </summary>
	uint GetMaxWaitObjectCount() const
	{
		return 1;
	}

	/// <summary>
	/// Get the wait objects pending on the call stack
	/// </summary>
	/// 
	/// <param name="Container">The receiving wait object container</param>
	/// <param name="Stack">The call stack</param>
	void GetWaitObjects(WaitObjectContainer &Container, const CallStack &Stack);
};


NAMESPACE_NETWORKEND