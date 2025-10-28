# ECDSA Attacks — Bad nonce for the win 💥

![GitHub License](https://img.shields.io/badge/license-MIT-blue)
![Sage Badge](https://img.shields.io/badge/built%20with-SageMath-2b6db0)
![Language](https://img.shields.io/badge/language-Sage%2FPython-3572A5)

A series of attacks against faulty ECDSA implementations — completed as part of the *Industrial Cryptography (MA-ICR)* course at the *University of Applied Sciences and Arts (HES-SO)*.

This repository demonstrates practical exploits that recover ECDSA private keys when the ephemeral nonce `k` is generated poorly (biased, partially leaked, or otherwise predictable).

Problem set is the courtesy of Prof. Alexandre Duc, All Rights Reserved ©. Solutions in this repository are released under the MIT license.

# How these attacks work (in a nutshell)

## Challenge #1

The first challenge uses the `sign1` function to sign messages using ECDSA.

```python
def sign1(G, m, n, a):
    F = Integers(n)
    n2 = n // 2 ^ 32 # Hack to have small randomness
    k = F(ZZ.random_element(n2))
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))
```

The nonce has bad randomness, and is 32 bits too small. Because the nonce is bounded to the value $B = 2^{log_2(n) - 32}$, we can use a lattice-attack[^1] to retreive the private key. For that, we have access to 20 messages and their respective signatures, as well as the public key.

To solve for the private key, we have to translate our ECDSA problem into a hidden number problem of the following form: 

$$t_i\alpha - a_i \mod p = b_i \text{ with } b_i < B$$


Using the ECDSA formula, we can establish the following relationships:

$$p = n$$

$$a_i = \frac{r_i}{s_i}$$

$$t_i = -\frac{h(m_i)}{s_i}$$

$$B = 2^{log_2(n) - 32}$$

Then, we can build the HNP lattice matrix $M$[^1], and apply the LLL algorithm. This results in a new matrix $M'$, which has shorter vectors. In this matrix $M'$, we hope that one of the vectors has the form

$$v_b = (b_1, b_2, b_3, \dots, b_m, -B\alpha/p, B)$$

so that we can recover $\alpha$. For that, we take each row of the matrix $M'$, solve for $\alpha$, recompute the public key, and compare it to the given public key.

[^1]:https://eprint.iacr.org/2019/023.pdf

## Challenge #2

The second challenge uses the `sign2` function to sign messages using ECDSA.
```python
def sign2(G, m, n, a):
    F = Integers(n)
    key = hashlib.sha256(m).digest()
    nonce = b"\x00" * 24
    cipher = ChaCha20.new(key=key, nonce=nonce)
    size_n = ceil(RR(log(n, 2)) / 8)
    k = int.from_bytes(cipher.encrypt(b"\x00" * size_n))
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))
```

Here, the issue is that the nonce is not randomly generated, but is deterministic instead. It is computed based on the message. This means that for a message $m$, the component $r$ of the signature will always be the same. In this particular case, the nonce is computed using a ChaCha20 stream cipher.

Using this vulnerability, we can recover the nonce by computing it ourselves. Once the nonce is known, we can recover the private key using one of the 20 given signatures and messages.

$$\alpha = \frac{sk - h(m)}{r}$$

We can check the private key by recomputing the public key and comparing it to the given public key.

## Challenge #3

The third challenge uses the `sign3` function to sign messages using ECDSA.

```python
def sign3(G, m, n, a):
    F = Integers(n)
    key = hashlib.sha256(str(a).encode()).digest()
    nonce = hashlib.sha256(str(a).encode()).digest()[:24]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    size_n = ceil(RR(log(n, 2)) / 8)
    k = int.from_bytes(cipher.encrypt(b"\x00" * size_n))
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))
```

Here, as for challenge #2, the nonce is deterministic. However, in that case, we can not compute the nonce directly, because it is based on the private key. But because it is based solely on the private key, we can combine two signatures to recover the nonce $k$.


For two signatures $(r, s)$ and $(r, s')$

$$
\begin{align*}
s &= \frac{\alpha + h(m)}{k} \\
s' &= \frac{\alpha + h(m')}{k} \\
s - s' &= \frac{h(m) - h(m')}{k} \\
k &= \frac{h(m) - h(m')}{s - s'}
\end{align*}
$$

We can simply use two of the given signatures to solve for $k$. Once $k$ is known, we can recover the private key as we did in challenge 2.

## Challenge #4

The fourth challenge uses the `sign4` function to sign messages using ECDSA.

```python
def sign4(G, m, n, a):
    F = Integers(n)
    k = int(hashlib.sha256(str(a).encode() + str(m).encode()).hexdigest(), 16)
    (x1, y1) = (k * G).xy()
    r = F(x1)
    return (r, (F(h(m)) + a * r) / F(k))
```

Here, the nonce is deterministic, but is built using both the message and the private key. In addition, those values are passed in a hash function, which is hard to reverse. In theory, recovering $k$ using the techniques from challenge \#2 and \#3 seems to be impossible. However, the hash function used is SHA256, which has an output of 256 bits. This is small when compared to the required size of 384 bits. In challenge \#1, the nonce was only 32 bits smaller than the required size, and we were able to recover the nonce using a lattice-attack. In this case, the nonce is 128 bits smaller than the required size. Theoretically, we can use the same attack on this challenge, by simply adapting the bound $B$. In this case, the bound $B=2^{256}$.

```python
B = pow(2, 256)
```

# Mitigations

If you’re asked how to fix these issues in real systems: Do not reuse nonces, and do not use predictable deterministic nonces. Instead, use a secure, cryptographically strong RNG output of at least 384 bits.

# Security & ethics

This repository is intended for educational and defensive purposes only: to learn how ECDSA fails when used incorrectly and to help implement robust, secure systems. Do **not** use these techniques for unauthorized access or malicious activity. If you discover a real vulnerability, follow responsible disclosure practices.

# Acknowledgements

* Prof. Alexandre Duc — original problem set and template.