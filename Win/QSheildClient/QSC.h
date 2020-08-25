#ifndef QSHEILD_QSC_H
#define QSHEILD_QSC_H

#include "Common.h"
#include "ConsoleTools.h"
#include "MessageIndex.h"
#include "../../CEX/InternetAddress.h"
#include "../../CEX/SecureVector.h"
#include "../../CEX/SocketExceptions.h"
#include "../../CEX/SocketClient.h"

namespace QuantumShield
{
	using CEX::ipv4_address;
	using CEX::ipv6_address;
	using CEX::SecureVector;
	using CEX::Network::Socket;
	using CEX::Enumeration::SocketExceptions;
	using CEX::Network::SocketClient;

	/// <summary>
	/// QSS state options
	/// </summary>
	class QSCState final
	{
	public:

		bool IPv6Enabled;
		bool MultiThreaded;
		std::string UserName;

		QSCState()
			:
			IPv6Enabled(false),
			MultiThreaded(false),
			UserName("")
		{
		}

		~QSCState()
		{
			IPv6Enabled = false;
			MultiThreaded = false;
			UserName.clear();
		}
	};

	class QSC final
	{
	private:

		static const size_t QSC_MENU_SIZE = 36;
		static const ushort QSC_DEF_PORT = 1776;
		static const std::string QSC_KEY_EXTENSION;
		static const std::string QSC_COMMAND_PROMPT;
		static std::vector<std::string> MessageStrings;

		QSCState m_serverState;
		SocketClient m_clientSocket;
		std::vector<Socket> m_socketPool;
		bool m_isRunning;

	public:

		//~~~Constructor~~~//

		/// <summary>
		/// The constructor
		/// </summary>
		///
		/// <param name="State">The server state</param>
		QSC(QSCState &State);

		/// <summary>
		/// The destructor
		/// </summary>
		~QSC();

		//~~~Public Functions~~~//

		/// <summary>
		/// Start and instance of the server listener
		/// </summary>
		///
		/// <param name="Address">The IPv4 address structure</param>
		/// <param name="Port">The listening port number</param>
		void Run(const ipv4_address &Address, ushort Port = QSC_DEF_PORT)
		{
			std::function<void(int, const std::string&)> socketconnectedhandler = [this](int x, const std::string &y) { SocketConnected(x, y); };
			m_clientSocket.OnSocketConnected += socketconnectedhandler;

			std::function<void(int, const std::string & y)> socketdisconnectedhandler = [this](int x, const std::string &y) { SocketDisconnected(x, y); };
			m_clientSocket.OnSocketDisconnected += socketdisconnectedhandler;

			std::function<void(int, const std::vector<byte>&)> socketreceivedhandler = [this](int x, const std::vector<byte> &y) { SocketReceived(x, y); };
			m_clientSocket.OnSocketReceived += socketreceivedhandler;

			std::function<void(int)> socketsendhandler = [this](int x) { SocketSend(x); };
			m_clientSocket.OnSocketSent += socketsendhandler;

			if (m_serverState.MultiThreaded)
			{

			}
			else
			{
				if (!m_clientSocket.Connect(Address, Port))
				{
					ConsoleTools::Print("Client could not connect to the remote host!");
				}
				
			}
		}

		/// <summary>
		/// Start and instance of the server listener
		/// </summary>
		///
		/// <param name="Address">The IPv6 address structure</param>
		/// <param name="Port">The listening port number</param>
		void Run(const ipv6_address &Address = ipv6_address::LoopBack(), ushort Port = QSC_DEF_PORT);

		/// <summary>
		/// Shutdown the server
		/// </summary>
		void Quit()
		{
			m_clientSocket.ShutDown();
		}

		/// <summary>
		/// RBlocking receive data from the remote host
		/// </summary>
		///
		/// <param name="Output">The data received</param>
		uint Receive()
		{
			return m_clientSocket.Receive(1200);
		}

		/// <summary>
		/// Send data to the remote host
		/// </summary>
		///
		/// <param name="Input">The data to send</param>
		void Send(const std::vector<byte> &Input)
		{
			m_clientSocket.Send(Input, Input.size());
		}

		//~~~Callbacks~~~//

		/// <summary>
		/// A socket has been connected
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		/// <param name="Connection">The connection socket</param>
		void SocketAccepted(int Identity, Socket &Connection)
		{
			m_socketPool.push_back(Connection);
		}

		/// <summary>
		/// A socket has been closed
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		/// <param name="Message">The servers shutdown message</param>
		void SocketDisconnected(int Identity, const std::string &Message)
		{
			ConsoleTools::Print("Client disconnected: " + Message);
		}

		/// <summary>
		/// A socket has been connected
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		void SocketConnected(int Identity, const std::string &Message)
		{
			ConsoleTools::Print("Client connected: " + Message);
		}

		/// <summary>
		/// An error has occured
		/// </summary>
		///
		/// <param name="Error">The socket exception code</param>
		/// <param name="Message">The error message</param>
		void SocketError(SocketExceptions Error, const std::string &Message)
		{
			ConsoleTools::Print("Client error: " + Message);
		}

		/// <summary>
		/// A socket has received data from the remote host
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		/// <param name="Output">Data received from the remote host</param>
		void SocketReceived(int Identity, const std::vector<byte> &Output)
		{
			std::string msg((char*)Output.data());

			ConsoleTools::Print("Remote> " + msg);
		}

		/// <summary>
		/// The socket has sent data to the remote host
		/// </summary>
		///
		/// <param name="Identity">The sockets reference number</param>
		void SocketSend(int Identity)
		{
			ConsoleTools::Print("Data has been transmitted");
		}

		//~~~Static Functions~~~//

		/// <summary>
		/// Ask the user a question posed Y or N
		/// </summary>
		///
		/// <param name="Index">The message index</param>
		static bool UserQuery(MessageIndex Index);

		/// <summary>
		/// Display the help menu
		/// </summary>
		static void Help();

		/// <summary>
		/// Print the application title
		/// </summary>
		static void PrintTitle();

		/// <summary>
		/// Print a message to the console
		/// </summary>
		///
		/// <param name="Index">The message index</param>
		static void PrintMessage(MessageIndex Index);

	private:

		static size_t LanguageIndex();
	};
}

#endif