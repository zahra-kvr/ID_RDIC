
# Identity-Based Remote Data Integrity Checking with Perfect Data Privacy
> Bachelor's Project Implementation

Implementation of the identity-based remote data integrity checking protocol with perfect data privacy preserving for cloud storage, based on the paper by **Yong Yu et al.**

## Reference

> Yong Yu, "Identity-based remote data integrity checking with perfect data privacy preserving for cloud storage"


<!-- > **Author**: [Your Name] | **Supervisor**: [Professor Name] | **Year**: 2025/2026 -->

---

## Overview

This project implements a cryptographic protocol that allows a Third-Party Auditor (TPA) or data owner to verify the integrity of data stored on a remote cloud server without downloading the entire file, while preserving perfect data privacy. The scheme uses:

- **Identity-Based Cryptography**: Private keys derived from user identities via a Key Generation Center (KGC), using the Boneh et al. short signature algorithm
- **Symmetric Bilinear Pairings**: SS512 curve with pairing $e: \mathbb{G}_1 \times \mathbb{G}_1 \rightarrow \mathbb{G}_T$
- **Perfect Data Privacy**: The server learns nothing about the actual file blocks during auditing, as the response is masked through the $H_3$ hash function

## Protocol Phases

### Setup
The KGC chooses cyclic groups $\mathbb{G}_1$, $\mathbb{G}_T$ with prime order $q$, generator $g \in \mathbb{G}_1$, and bilinear map $e: \mathbb{G}_1 \times \mathbb{G}_1 \rightarrow \mathbb{G}_T$. It picks master secret key $\alpha \in \mathbb{Z}^*_q$ and computes $P_{\text{pub}} = g^\alpha$. Three hash functions are defined:
- $H_1, H_2: \{0,1\}^* \rightarrow \mathbb{G}_1$
- $H_3: \mathbb{G}_T \rightarrow \{0,1\}^l$

System parameters: $(\mathbb{G}_1, \mathbb{G}_T, e, g, P_{\text{pub}}, H_1, H_2, H_3, l)$

### Extract
Given identity $\text{ID} \in \{0,1\}^*$, the KGC outputs the user's private key:
$$sk = H_1(\text{ID})^\alpha$$

### TagGen
The data owner divides file $M$ into $n$ blocks $m_1, \dots, m_n \in \mathbb{Z}_q$, picks random $\eta \in \mathbb{Z}^*_q$, and computes $r = g^\eta$. For each block:
$$\sigma_i = sk^{m_i} \cdot H_2(\text{fname}||i)^\eta$$
The file is stored on the cloud together with $(r, \{\sigma_i\}, \text{IDS}(r||\text{fname}))$.

### Challenge
The verifier picks a random $c$-element subset $I \subset [1,n]$ with random values $v_i \in \mathbb{Z}^*_q$, forming $Q = \{(i, v_i)\}$. It picks $\rho \in \mathbb{Z}^*_q$, computes $Z = e(H_1(\text{ID}), P_{\text{pub}})$, and sends:
$$c_1 = g^\rho, \quad c_2 = Z^\rho, \quad \text{chal} = (c_1, c_2, Q, \text{pf})$$

### GenProof
The server verifies the proof $\text{pf}$, then computes:
$$\mu = \sum_{i \in I} v_i \cdot m_i$$
$$\sigma = \prod_{i \in I} \sigma_i^{v_i}$$
$$m' = H_3\left(e(\sigma, c_1) \cdot c_2^{-\mu}\right)$$
Returns $(m', r, \text{IDS}(r||\text{fname}))$.

### CheckProof
The verifier checks the identity-based signature $\text{IDS}(r||\text{fname})$, then verifies:
$$m' = H_3\left( \prod_{i \in I} e\left(H_2(\text{fname}||i)^{v_i}, r^\rho\right) \right)$$

## Requirements

```
charm-crypto
textual
```

Install dependencies:
```bash
pip install charm-crypto textual
```

## Usage

Run the ID_RDIC TUI application:
```bash
python ID_RDIC.py
```

### Workflow

1. **Extract Private Key**: Generate a key for a user identity via the KGC ($sk = H_1(\text{ID})^\alpha$)
2. **Upload & Sign File**: Segment file, generate tags ($\sigma_i = sk^{m_i} \cdot H_2(\text{fname}||i)^\eta$), and store with random value $r$
3. **Audit Single File**: Challenge-response verification using $(c_1, c_2)$ encryption and $H_3$ masking
4. **Batch Audit All**: Verify integrity of all stored files simultaneously
5. **Corrupt Storage**: Simulate data corruption to test audit detection
6. **Delete File**: Remove a file from server storage

## Architecture

$$
\begin{aligned}
&\text{KGC Setup} \rightarrow \alpha, \; P_{\text{pub}} = g^\alpha \\
&\downarrow \\
&\text{Extract(ID)} \rightarrow sk = H_1(\text{ID})^\alpha \\
&\downarrow \\
&\text{TagGen} \rightarrow \eta, \; r = g^\eta, \; \sigma_i = sk^{m_i} \cdot H_2(\text{fname}||i)^\eta \\
&\downarrow \\
&\text{Server stores } (\text{blocks}, \{\sigma_i\}, r) \\
&\downarrow \\
&\text{Challenge} \rightarrow \rho, \; c_1 = g^\rho, \; c_2 = e(H_1(\text{ID}), P_{\text{pub}})^\rho \\
&\downarrow \\
&\text{GenProof} \rightarrow \mu = \sum v_i \cdot m_i, \; \sigma = \prod \sigma_i^{v_i}, \; m' = H_3\left(e(\sigma, c_1) \cdot c_2^{-\mu}\right) \\
&\downarrow \\
&\text{CheckProof} \rightarrow \text{verify } m' = H_3\left(\prod e\left(H_2(\text{fname}||i)^{v_i}, r^\rho\right)\right)
\end{aligned}
$$
