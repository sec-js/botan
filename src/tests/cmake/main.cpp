#include <botan/version.h>
#include <iostream>

int main() {
   std::cout << Botan::version_string() << std::endl;
   return 0;
}
