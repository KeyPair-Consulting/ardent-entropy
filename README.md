# KeyPair Entropy Provider (KPEP) for OpenSSL 3.5.x

## Origin

Started as KPMP (part of KPFP+), modified to standalone FIPS provider

## Modifications

Notable large-scale changes:

* Remove KDFs and associated CASTs
* Remove interop/interdependence with KPFP
* Update names and labels
* Modify install script

Long Term Plans:

* Integrate into OpenSSL tree and build system
* Use OpenSSL built-in threading and mutex to handle async operation
* Allow operation as an RBG2 construction
