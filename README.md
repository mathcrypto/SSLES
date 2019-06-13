# [SSLES](https://ethresear.ch/t/cryptographic-sortition-possible-solution-with-zk-snark/5102)
Single Secret Leader Election Snark (Block Proposer privacy Protocol using ZKSnarks):


Public parameters:

- A public random number `m `(emitted by the random beacon).
- The roothash of all the participants’ public keys: `rh`.
- `h = hash(signed(m))`

Secret parameters:

- Sign the message `m` by all participants: `signed(m)`
- The signer’s public key: `pk`
- Merkled path: `mp`

**Protocol**
- Generate `N` signature pairs pub/priv pair, we generate a SNARK (since participants have to send proof that they are eligible). 
- We choose one party `hash h` to be the block proposer.
- The party that was chosen will publish the sig that proves they are the right person.
- The other parties verify the sig to verify if  the msg m was actually signed by the corresponding private key.


**Checks performed by the ZK-SNARK:**
1. The public key belongs to one of the participants: the Merkle path `mp` leads from the public key `pk` to the root hash `rh`.

2. `Signed(m)` checks out against the public key `pk` and the random number `m`. 

3. `Hash(signed(m))` given in the public parameters is the hash of `signed(m)` given in the secret parameters.

4. `Signed(m)` in the secret parameters is the same `m given in the public parameters.




# Build instructions

Fetch dependencies from their GitHub repos:

``$ git submodule init && git submodule update``

Create the Makefile:

``$ mkdir build && cd build``

   ``LD_LIBRARY_PATH=/usr/local/opt/openssl/lib:"${LD_LIBRARY_PATH}"  ``              
      ``CPATH=/usr/local/opt/openssl/include:"${CPATH}"   ``                                
     `` PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig:"${PKG_CONFIG_PATH}" ``      
     `` export LD_LIBRARY_PATH CPATH PKG_CONFIG_PATH `` 
      ``CPPFLAGS=-I/usr/local/opt/openssl/include LDFLAGS=-L/usr/local/opt/openssl/lib``
      ``PKG_CONFIG_PATH=/usr/local/opt/openssl/lib/pkgconfig cmake -DWITH_PROCPS=OFF -DWITH_SUPERCOP=OFF ..``


  Then, to compile the library, tests, and profiling harness, run this within the build directory:

``$ make``

