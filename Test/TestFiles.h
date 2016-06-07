#ifndef _CEXTEST_TESTFILES_H
#define _CEXTEST_TESTFILES_H

#include <string>

namespace TestFiles
{
    namespace AESAVS 
	{
        const std::string keyvect128 = "Vectors/AESAVS/keyvect128.txt";
        const std::string keyvect192 = "Vectors/AESAVS/keyvect192.txt";
        const std::string keyvect256 = "Vectors/AESAVS/keyvect256.txt";
        const std::string plainvect128 = "Vectors/AESAVS/plainvect128.txt";
        const std::string plainvect192 = "Vectors/AESAVS/plainvect192.txt";
        const std::string plainvect256 = "Vectors/AESAVS/plainvect256.txt";
    }
    
	namespace Counterpane 
	{
		const std::string twofishcipher128 = "Vectors/Counterpane/twofishcipher128.txt";
		const std::string twofishcipher192 = "Vectors/Counterpane/twofishcipher192.txt";
		const std::string twofishcipher256 = "Vectors/Counterpane/twofishcipher256.txt";
		const std::string twofishkey128 = "Vectors/Counterpane/twofishkey128.txt";
		const std::string twofishkey192 = "Vectors/Counterpane/twofishkey192.txt";
		const std::string twofishkey256 = "Vectors/Counterpane/twofishkey256.txt";
	}

    namespace Nessie 
	{
        const std::string serpentcipher128 = "Vectors/Nessie/serpentcipher128.txt";
        const std::string serpentcipher192 = "Vectors/Nessie/serpentcipher192.txt";
        const std::string serpentcipher256 = "Vectors/Nessie/serpentcipher256.txt";
        const std::string serpentkey128 = "Vectors/Nessie/serpentkey128.txt";
        const std::string serpentkey192 = "Vectors/Nessie/serpentkey192.txt";
        const std::string serpentkey256 = "Vectors/Nessie/serpentkey256.txt";
        const std::string serpentmonte100_128 = "Vectors/Nessie/serpentmonte100-128.txt";
        const std::string serpentmonte100_192 = "Vectors/Nessie/serpentmonte100-192.txt";
        const std::string serpentmonte100_256 = "Vectors/Nessie/serpentmonte100-256.txt";
        const std::string serpentmonte1000_128 = "Vectors/Nessie/serpentmonte1000-128.txt";
        const std::string serpentmonte1000_192 = "Vectors/Nessie/serpentmonte1000-192.txt";
        const std::string serpentmonte1000_256 = "Vectors/Nessie/serpentmonte1000-256.txt";
        const std::string serpentplain128 = "Vectors/Nessie/serpentplain128.txt";
        const std::string serpentplain192 = "Vectors/Nessie/serpentplain192.txt";
        const std::string serpentplain256 = "Vectors/Nessie/serpentplain256.txt";
    }
}

#endif
