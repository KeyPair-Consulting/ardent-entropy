# KeyPair Entropy Provider (KPEP) for OpenSSL 3.5.x

Started as KPMP (part of KPFP+), modified to a standalone FIPS provider

## Change List

### FUTURE PLANS

* Integrate into OpenSSL tree and build system
* Allow operation as an RBG2 construction

### 0.0.4

* Use OpenSSL built-in threading and mutex to handle async operation
* Make seed sources async by using per-source ring buffer fed by threaded gather
* Improved logging and tracing
* Improved locking and race condition hardening

### 0.0.3

* Integrate changes from the "EVAL" version of KPMP (v1.0.3)

### NOTE: I wasn't tracking versions too heavily before this point, but roughly...

### 0.0.2

* Remove KDFs and associated CASTs
* Remove interop/interdependence with KPFP
* Update names and labels
* Modify install script

### 0.0.1

* Original KPMP source code
