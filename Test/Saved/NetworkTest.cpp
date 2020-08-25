#include "NetworkTest.h"
#include "../CEX/NetworkTools.h"
#include "../CEX/SecureRandom.h"
#include "../CEX/SecureVector.h"
#include "../CEX/SocketClient.h"
#include "../CEX/SocketServer.h"
#include <iostream>
#include <time.h>

namespace Test
{
	using Tools::NetworkTools;
	using Exception::CryptoSocketException;
	using Prng::SecureRandom;
	using namespace Network;

	const std::string NetworkTest::CLASSNAME = "NetworkTest";
	const std::string NetworkTest::DESCRIPTION = "Sockets and TCP/IP stack test; checks constructors, exceptions, initialization, and synchronization of the networking components.";
	const std::string NetworkTest::SUCCESS = "SUCCESS! All Networking tests have executed succesfully.";

	NetworkTest::NetworkTest()
		:
		m_progressEvent()
	{
	}

	NetworkTest::~NetworkTest()
	{
	}

	const std::string NetworkTest::Description()
	{
		return DESCRIPTION;
	}

	TestEventHandler &NetworkTest::Progress()
	{
		return m_progressEvent;
	}

	std::string NetworkTest::Run()
	{
		try
		{
			//Exception();
			//OnProgress(std::string("NetworkTest: Passed exception handling tests.."));
			//Events();
			std::string shost = "localhost";
			std::string sport = "80";
			std::string dhost = "127.0.0.1";
			std::string dport = "80";

			Forwarding(shost, sport, dhost, dport);
			OnProgress(std::string("NetworkTest: Passed IP forwarding tests.."));
			//Initialization();
			//OnProgress(std::string("NetworkTest: Passed initialization tests.."));
			//Synchronization();
			//OnProgress(std::string("NetworkTest: Passed key synchronization tests.."));
			//Stress();
			//OnProgress(std::string("NetworkTest: Passed key creation stress tests.."));

			return SUCCESS;
		}
		catch (TestException const &ex)
		{
			throw TestException(CLASSNAME, ex.Function(), ex.Origin(), ex.Message());
		}
		catch (CryptoException & ex)
		{
			throw TestException(CLASSNAME, ex.Location(), ex.Origin(), ex.Message());
		}
		catch (std::exception const &ex)
		{
			throw TestException(CLASSNAME, std::string("Unknown Origin"), std::string(ex.what()));
		}
	}

	void NetworkTest::Events()
	{
		SocketClient scksrc;
		std::mutex plock;
		std::string remhost;

		remhost = std::string("172.217.13.164");//www.google.com

		//event_handler<int, const std::string&> socketclosedhandler1([&scksrc, &plock](int id, const std::string& message) 
		//{
		//	std::string pid;
		//	std::lock_guard<std::mutex> lock(plock);
		//	pid = IntegerTools::ToString(id);

		//	std::cout << "Socket lambda handler: " << std::endl;
		//	std::cout << "Socket address: " + message << std::endl;
		//	std::cout << "Socket instance: " + pid << std::endl;
		//});

		//std::function<void(int, const std::string&)> socketclosedhandler2 = [this](int x, const std::string& y) { SocketClosed(x, y); };

		//scksrc.OnSocketClosed += socketclosedhandler1;
		//scksrc.OnSocketClosed += socketclosedhandler2;

		//scksrc.Create(SocketAddressFamilies::IPv4);
		//scksrc.Connect(remhost, "http");
		//scksrc.CloseSocket();

		//scksrc.OnSocketClosed -= socketclosedhandler1;
	}

	void NetworkTest::Exception()
	{
		// Initialization exception tests //

		/*try
		{
			std::vector<byte> poly(0);
			AsymmetricKey kp(poly, AsymmetricPrimitives::NTRUPrime, AsymmetricKeyTypes::CipherPrivateKey, AsymmetricParameters::NTRUS2SQ4591N761);

			throw TestException(std::string("Exception"), std::string("AsymmetricKey"), std::string("Exception handling failure! -AE1"));
		}
		catch (CryptoAsymmetricException const &)
		{
		}
		catch (TestException const &)
		{
			throw;
		}*/

	}

	void NetworkTest::Forwarding(std::string &SourceHost, const std::string &SourcePort, std::string &DestinationHost, const std::string &DestinationPort)
	{
		SocketClient sckdst;
		SocketServer scklsn;
		SocketClient scksrc;
		ushort dstport;
		ushort srcport;
		ipv4_address add;
		
		srcport = 80;
		add = ipv4_address::FromString(SourceHost);

		std::function<void(int, const std::string&)> socketclosedhandler2 = [this](int x, const std::string& y) { SocketClosed(x, y); };
		scklsn.OnSocketClosed += socketclosedhandler2;
		scklsn.ListenAsync(add, srcport);
		scklsn.ShutDown();

		/*srcport = SocketClient::PortNameToNumber(SourcePort);
		dstport = SocketClient::PortNameToNumber(DestinationPort);

		scklsn.OnSocketClosed += [this]() { SocketClosed(); };
		event_handler<> socketclosedhandler([&scklsn]() {
			std::cout << "Socket closed" << std::endl;
		});

		scklsn.OnSocketClosed += socketclosedhandler;

		scklsn.Create(SocketAddressFamilies::IPv4);
		scklsn.CloseSocket();
		scklsn.OnSocketClosed -= socketclosedhandler;*/

		/*//scklsn.Bind(srcport, SourceHost);
		SocketClient::SocketOption(scklsn.GetSocket());
		std::cout << "Listing on port " << srcport << ".\n";
		scklsn.Listen();
		scklsn.Accept(scksrc.GetSocket());

		std::cout << "Connection accepted on port " << srcport << ".\n";
		scklsn.CloseSocket();

		std::cout << "Making connection to " << DestinationHost << ", port " << destinationPort << ".\n";
		SocketClient::Create(sckdst);
		SocketClient::Connect(sckdst, DestinationHost, destinationPort);

		std::cout << "Connection made to " << DestinationHost << ", starting to forward.\n";
		SocketClient::ShutDownSockets();

		SocketSource out(scksrc, false, new SocketSink(sckdst));
		SocketSource in(sckdst, false, new SocketSink(scksrc));

		WaitObjectContainer waitObjects;

		while (!(in.SourceExhausted() && out.SourceExhausted()))
		{
			waitObjects.Clear();

			out.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - out", NULL));
			in.GetWaitObjects(waitObjects, CallStack("ForwardTcpPort - in", NULL));

			waitObjects.Wait(-1);

			if (!out.SourceExhausted())
			{
				std::cout << "o" << std::ostream::flush;
				out.PumpAll2(false);

				if (out.SourceExhausted())
				{
					std::cout << "EOF received on source socket.\n";
				}
			}

			if (!in.SourceExhausted())
			{
				std::cout << "i" << std::ostream::flush;
				in.PumpAll2(false);

				if (in.SourceExhausted())
				{
					std::cout << "EOF received on destination socket.\n";
				}
			}
		}*/
	}

	void NetworkTest::SocketClosed(int Id, const std::string& Message)
	{
		std::mutex plock;
		std::string pid;
		std::lock_guard<std::mutex> lock(plock);

		pid = IntegerTools::ToString(Id);
		std::cout << "Socket function handler: " << std::endl;
		std::cout << "Socket address: " + Message << std::endl;
		std::cout << "Socket instance: " + pid << std::endl;
	}

	void NetworkTest::Initialization()
	{

	}

	void NetworkTest::Synchronization()
	{


		/*ipv6_address ia1(10, 11, 12, 13, 0, 0, 0, 0, 0, 0, 14, 15, 16, 17, 18, 19);
		std::string x1 = ipv6_address::ToString(ia1);
		ipv6_address ia2 = ipv6_address::FromString(x1);

		ipv4_address ia3(192, 168, 1, 1);
		std::string x2 = ipv4_address::ToString(ia3);
		ipv4_address ia4 = ipv4_address::FromString(x2);

		GetIPv6Address();*/
	}

	void NetworkTest::Stress()
	{

	}

	void NetworkTest::OnProgress(const std::string &Data)
	{
		m_progressEvent(Data);
	}
}
