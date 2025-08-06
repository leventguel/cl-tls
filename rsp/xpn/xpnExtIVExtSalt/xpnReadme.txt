XPN sample vectors

GCM-AES-XPN-128 and GCM-AES-XPN-256 with externally generated IV and externally generated Salt value.

The XPN directory contains three subdirectories:

1. req - "request" files, i.e., those files that are given to the vendor with CAVS-generated input values.

2. sample - "sample" files, i.e., those that indicate with a "?" where the IUT-generated values belong.

3. resp - "response" files, i.e., files with IUT-generated values inserted where indicated in "sample" files.  In
          the files provided, correct values are in all fields.


Note - it is also possible to test GCM-AES-XPN with an internally generated IV and/or internally generated Salt.
We do not provide sample test vectors for these because the IUT itself provides the IV and/or Salt values.
Instead, the following indicate test cases from a sample file with...

External IV and Internal Salt:
------------------------------
[Keylen = 128]
[IVlen = 96]
[PTlen = 256]
[AADlen = 256]
[Taglen = 128]

Count = 0
Key = 79e2714070dad003cc3d65778f0c71c5
IV = 95731427618fa8d7bf85f265
PT = 85ca6e06548feef46c9467dbc1a553ee6e8f8dc5512c140619ead5a978b930c1
AAD = faedda740f78a24dda6d0e37ade4fad4aa390e3895a72b2beab4a3089ca41a2c
Salt = ?
CT = ?
Tag = ?


Internal IV and External Salt:
------------------------------
[Keylen = 256]
[IVlen = 96]
[PTlen = 136]
[AADlen = 136]
[Taglen = 112]

Count = 0
Key = 7bf0d177414c355c789d18bc05b7807c642a7b86081db99d3da64075a593c337
Salt = 8d63987630104e3d2eb62a73
PT = 345572aa45b18d34ea50e2133cb78b4877
AAD = 42d719dd5a42670b4de3452f47dddf5264
IV = ?
CT = ?
Tag = ?


Internal IV and Internal Salt:
------------------------------
[Keylen = 128]
[IVlen = 96]
[PTlen = 256]
[AADlen = 264]
[Taglen = 32]

Count = 0
Key = 3786c4ae8139c67542100acd494d0287
PT = 9a907d9dfac02fab5a787502f8d810964c227f402e1ad33a3be46d273c2ee656
AAD = b317aa2ca7e08e6f72cad77a61e5f7e00c065b561f8eaf54789db81eba55d79805
Salt = ?
IV = ?
CT = ?
Tag = ?