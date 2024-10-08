/*
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "fuzzers.h"

#include <botan/data_src.h>
#include <botan/x509_crl.h>

void fuzz(std::span<const uint8_t> in) {
   try {
      Botan::DataSource_Memory input(in);
      Botan::X509_CRL crl(input);
   } catch(Botan::Exception& e) {}
}
