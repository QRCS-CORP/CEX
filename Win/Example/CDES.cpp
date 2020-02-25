#include "CDES.h"

namespace Example
{
	//~~~Public Functions~~~//

	void CDES::Run()
	{

	}

	void CDES::Help()
	{

	}

	void CDES::PrintTitle()
	{
		ExampleUtils::WriteLine("CDES - CEX File Encryption Service");
		ExampleUtils::WriteLine("Version 1.0a");
		ExampleUtils::WriteLine("January 12, 2020");
		ExampleUtils::WriteLine("CEX++ -Digital Freedom Defence-");
		ExampleUtils::WriteLine("");
	}

	//~~~Private Functions~~~//

	void CDES::SecureGenerate(SecureVector<byte> &Output, size_t Offset, size_t Length)
	{
		ACP gen;

		gen.Generate(Output, Offset, Length);
	}
}