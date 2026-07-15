## Column Description

**e2c_total_bytes:** Total bytes transferred during the handshake (Client - Server)
* **Handshake:** an initial exchange between client and server where they establish rules of communication before the actual data exchange. In this case, the handshake is where the client and server negotiate encryption algorithms, exchange certificates, and exchange keys.



**e4_entropy_h:** Shannon entropy of the Client Hello / Server Hello headers.
* **Shannon entropy:** is the randomness score, how predictable/unpredictable the text is.
* **Client Hello / Server Hello headers:** are the first messages exchanged to setup a secure connection. 
* meaning e4_entropy_h measures how random/unpredicatable are the Client Hello / Server Hello



**e5_entropy_c:** Shannon entropy of the encrypted ciphertext payload (first 4KB)
* This measures how random/unpredictable is the content of the encrypted ciphertext first 4KB. the more random the ciphertext is, the better.



**e6_time_char:** undefined, not sure what exactly is it.



**e6b_flow_duration_ms:** Total handshake duration in milliseconds (critical for PQC latency profiling).



**e2_client_size:** Size of the Client Key Share (indicates KEM group, e.g., X25519 vs ML-KEM-768).
* The size of the client's public encryption key only, which gives indication on the used encryption algorithm.



**e2_client_record_len:** Length(size) of the Client Hello record as a whole (header + key share + extensions combined)

**e2_server_record_len:** Length of the Server Hello record (proxy for Certificate size + KEM Ciphertext)

**e3_cert_parsed:** A True/False flag for whether a certificate was present and successfully parsed in that session.

##

**e1_alg_suite_*:** One-hot vector indicating the negotiated Key Exchange Method (e.g., mlkem768, x25519).



**e1_alg_suite_Unknown(0x11eb) and e1_alg_suite_Unknown(0x11ec):**
* both of these are not real cryptographic algorithms, they seem to be placeholder labels for sessions where the observed algorithm identifier didn't match any known/standard value.

* e1_alg_suite_Unknown(0x11eb) seems to test a corrupted/malformed key, from the ID (column AJ) it is called **raf_robustness_malformed_keyshare**

* e1_alg_suite_Unknown(0x11ec) seems to test one simulating algorithm mimicry, from the ID column it is called **model_gray_rsa_mimicry**


**e1_alg_suite_mlkem768:** ML-KEM (Module-Lattice-based Key Encapsulation Mechanism):
* a post-quantum key exchange algorithm. it's a KEM (Key Encapsulation Mechanism)

**e1_alg_suite_mlkem1024:** From tthe same algorithm family as the previous one (mlkem768), but using a parameter set that targets a higher security level (roughly comparable to AES_256).

**e1_alg_suite_x25519:** elliptic-curve Diffie-Hellman algorithm, a classical pre-quantum public key exchange algorithm

