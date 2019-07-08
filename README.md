# [SSLES](https://ethresear.ch/t/cryptographic-sortition-possible-solution-with-zk-snark/5102)
Single Secret Leader Election Snark (Block Proposer privacy Protocol using ZKSnarks):


Public parameters:

- A public random number `m `(emitted by the random beacon).
- The roothash of all the participants’ public keys: `rh`.
- `h = hash(signed(m))`

Secret parameters:

- Sign the message `m` by all participants: `signed(m)`
- The signer’s public key: `pk`
- Merkle path: `mp`

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

```
git clone https://github.com/HarryR/ethsnarks.git

cd ethsnarks
make

```


To compile the library, tests, and profiling harness, run this within the SSLES directory:

``$ make``

