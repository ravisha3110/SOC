# CyberShield — Password Security Analyzer (Phase 4A)

## 1. Overview and Academic Purpose

The **CyberShield Password Security Analyzer** is an offline, multi-signal cybersecurity assessment engine designed to objectively evaluate password strength and detect common structural weaknesses.

In modern cybersecurity operations centers (SOC) and identity management architectures, weak credentials remain one of the primary vectors for initial access, credential stuffing, and brute-force attacks. Rather than relying on simplistic rules (such as merely checking length or character presence), CyberShield employs a multi-signal scoring model combining:
- Length thresholds (minimum recommended $\ge 12$, excessively short $< 8$)
- Character class diversity (lowercase, uppercase, numbers, symbols, Unicode)
- **Empirical Shannon Entropy** (measuring internal unigram unpredictability)
- **Theoretical Character Pool Entropy** (combinatorial search space baseline)
- **Demonstration Dictionary Matching** (instant identification of common passwords)
- **Multiword Phrase & Word-Separator Detection** (identifies recognizable compound phrases)
- **Predictable Year & Seasonal Pattern Detection** (catches calendar years like 2024–2026 and season/month combinations like Summer2026)
- **Structural Pattern Detection** (repeated characters, repeated sequences, sequential numbers/letters, keyboard walks, and l33t-speak masks)

---

## 2. Core Security & Privacy Safeguards

The analyzer enforces zero-trust privacy controls:

1. **Zero Credential Retention**: The analyzer does not store the password in any object attribute, cache, memory log, or history.
2. **Zero Plaintext Printing or Logging**: The raw password is never printed to stdout, logged to files, or included in debug messages.
3. **Sanitized Exception Handling**: If invalid types are supplied, exceptions contain generic error messages without reflecting the input.
4. **Zero Network Calls**: Operates 100% offline. No external APIs (such as HaveIBeenPwned or breach lookup endpoints) are called.
5. **Zero Database Storage**: Neither SQLite nor PostgreSQL is touched during analysis.
6. **Privacy-Preserving Structured Result**: The returned `PasswordAnalysisResult` dataclass is completely immutable (`frozen=True`) and contains only diagnostic metrics (length, scores, patterns, recommendations), never the submitted password or any reversible representation.

---

## 3. Mathematical Foundations: Entropy Metrics & Limitations

### A. Empirical Shannon Character-Distribution Entropy

Empirical Shannon entropy evaluates the **internal unpredictability** of characters within the password string based strictly on character frequency. It answers: *"How compressed or repetitive is the distribution of symbols in this specific password?"*

The formula is defined as:

$$H(X) = -\sum_{i=1}^{k} p(x_i) \log_2 p(x_i)$$

Where:
- $k$ is the number of distinct characters in the password.
- $p(x_i) = \frac{\text{count}(x_i)}{L}$ is the empirical probability (frequency) of character $x_i$.
- $L$ is the total character length of the password.

The total Shannon entropy in bits for the entire password is calculated as:

$$\text{Shannon Entropy Bits} = L \times H(X)$$

#### Assumptions & Scientific Limitations:
- **Independent and Identically Distributed (i.i.d.) Assumption**: Multiplying $H(X)$ by $L$ assumes that every character in the password was drawn independently from the same empirical frequency distribution. In human-generated passwords, characters are **not** independent; they follow linguistic syllables, dictionary roots, and keyboard proximity.
- **No Linguistic Awareness**: A standard dictionary word like `"unpredictably"` consists of 13 unique characters, giving it maximal internal Shannon entropy ($L \times \log_2(L)$), even though it is completely guessable in a single dictionary lookup.
- **What It Truly Detects**: Shannon entropy is effective at detecting extreme character repetition (e.g. `"aaaaaaaaaaaa"` yields $0.0\text{ bits}$ regardless of length).

---

### B. Theoretical Character Pool Entropy

Theoretical character pool entropy measures the size of the brute-force search space under the assumption that an attacker attempts an exhaustive combinatorial search against a password chosen uniformly at random from a known character set.

The formula is:

$$\text{Pool Entropy Bits} = L \times \log_2(R)$$

Where:
- $L$ is the password length.
- $R$ is the size of the active character pool based on detected categories:
  - Lowercase (`a-z`): $+26$
  - Uppercase (`A-Z`): $+26$
  - Digits (`0-9`): $+10$
  - Symbols/Punctuation: $+33$
  - Extended Unicode characters: $+128$

#### Assumptions & Scientific Limitations:
- **Uniform Randomness Assumption**: The formula assumes that every string in $R^L$ is equally likely to be chosen. In reality, humans do not pick characters uniformly at random from a pool of 95 ASCII symbols; they pick words, capitalize the first letter, append a year, and put an exclamation mark at the end.
- **Attacker Strategy Mismatch**: Real attackers do **not** brute-force uniformly across $R^L$. They use targeted wordlists, rule-based transforms (e.g., Hashcat rules), mask attacks, and Markov chains.

---

### C. Critical Distinction: Entropy vs. Real-World Cracking Resistance

| Metric | What it Measures | Real-World Limitation |
| :--- | :--- | :--- |
| **Shannon Entropy** ($L \times H(X)$) | Empirical variety and non-uniformity within the string. | Blind to vocabulary, grammar, and common phrases. |
| **Pool Entropy** ($L \times \log_2(R)$) | Combinatorial search space under ideal uniform random generation. | Vastly overestimates security when human-chosen patterns are present. |

> [!CAUTION]
> **Important Academic Principle**: Neither Shannon entropy nor Pool entropy represents a guaranteed measure of real-world password cracking time. A password must never be awarded maximum strength solely because it is long and has high character diversity. True strength evaluation requires structural pattern and phrase analysis.

---

## 4. Multiword Phrase, Year, and Structural Pattern Detection

CyberShield implements comprehensive structural pattern detectors to catch predictable human habits:

### 1. Recognizable Common Multiword Phrases
- Evaluates tokenized words separated by delimiters (`-`, `_`, `.`, ` `, etc.).
- If 2 or more tokens match common dictionary words (e.g., the famous XKCD construction `"correct"`, `"horse"`, `"battery"`, `"staple"`), the engine flags `"common_multiword_phrase"`.
- **Capping Rule**: Such passphrases are strictly **capped at a maximum score of 70 (or 65 if combined with a year suffix)**, ensuring they **cannot receive `VERY_STRONG`**.
- **Preservation of Uncommon Passphrases**: An uncommon passphrase (e.g., `"krypton-xylophone-quartz-zenith-8351!"`) does not match the common dictionary set, avoiding false penalties and correctly attaining `VERY_STRONG`.

### 2. Predictable Year Patterns
- Identifies 4-digit calendar years ($1900–2099$) occurring as a suffix, prefix, or standalone token (e.g., `-2026!`, `_2025`, `2024`).
- Flags `"predictable_year"` and applies a score penalty.

### 3. Seasonal / Month + Year Patterns
- Identifies combinations of seasons (`spring`, `summer`, `autumn`, `fall`, `winter`) or months (`january` through `december`) joined with a year (e.g., `Summer2026`, `Winter-2025!`, `October2024`).
- Flags `"seasonal_year_pattern"` and caps score at $\le 45$ (`MODERATE` or `WEAK`).

### 4. Common Word + Number Combinations
- Detects single dictionary words immediately followed by numbers (e.g., `Password123`, `Tiger99`, `Cyber2026`).
- Flags `"word_number_combination"` and caps score at $\le 35$ (`WEAK`).

### 5. Classic Structural Patterns
- **Repeated Characters**: 3+ consecutive identical symbols (`aaa`, `1111`).
- **Repeated Sequences**: Repeated syllables or substrings (`abcabc`, `passpass`).
- **Sequential Numeric Runs**: Contiguous ascending or descending numbers of length 3+ (`123`, `987`).
- **Sequential Alphabetic Runs**: Contiguous alphabetical runs of length 3+ (`abc`, `xyz`).
- **Keyboard Walks**: Contiguous QWERTY row walks (`qwerty`, `asdfgh`, `zxcv`).
- **L33t-Speak Substitutions**: Normalized against common dictionary passwords (`dr@g0n` $\rightarrow$ `dragon`).

---

## 5. Strength Classification & Scoring Rules

The engine produces an integer score from `0` to `100` and classifies passwords into 5 distinct tiers:

| Tier | Score Range | Description & Typical Characteristics |
| :--- | :---: | :--- |
| **`VERY_WEAK`** | 0 – 19 | Common dictionary word, extreme character repetition, or length $< 8$ with low diversity. |
| **`WEAK`** | 20 – 39 | Predictable patterns, word+number combinations, seasonal+year patterns, or leet-masked dictionary words. |
| **`MODERATE`** | 40 – 59 | Acceptable length (8–11 chars) with mixed categories, moderate entropy, or short common multiword phrases. |
| **`STRONG`** | 60 – 79 | Good length ($\ge 12$ chars) with 3–4 categories, high entropy, or common multiword phrases with predictable components. |
| **`VERY_STRONG`** | 80 – 100 | Long passphrase with uncommon words ($\ge 16$ chars) or high-entropy random string across 4 classes with zero predictable patterns. |

### Strict Hard Capping Rules
1. **Dictionary Match**: Capped at score $\le 10$, forced to `VERY_WEAK`.
2. **Leet Dictionary Mask**: Capped at score $\le 20$, forced to `WEAK`.
3. **Word + Year / Word + Number**: Capped at score $\le 35$, forced to `WEAK`.
4. **Seasonal + Year Pattern**: Capped at score $\le 45$, cannot exceed `MODERATE`.
5. **Common Multiword Phrase**: Capped at score $\le 70$ (or $\le 65$ with predictable year), **strictly prohibited from receiving `VERY_STRONG`**.
6. **Length $< 8$**: Capped at score $\le 35$, cannot exceed `WEAK`.
7. **Extreme Repetition** (Shannon bits $< 10.0$ on length $\ge 8$): Capped at score $\le 15$, forced to `VERY_WEAK`.

---

## 6. Example Outputs

### A. Recognizable Multiword Passphrase with Year Suffix (`Correct-Horse-Battery-Staple-2026!`)
*Previously misclassified as score 100 / VERY_STRONG. Now accurately penalized and capped:*

```json
{
  "strength": "STRONG",
  "score": 65,
  "length": 34,
  "character_diversity": 4,
  "character_categories": {
    "lowercase": true,
    "uppercase": true,
    "digits": true,
    "symbols": true
  },
  "shannon_entropy_bits": 134.97,
  "estimated_pool_entropy_bits": 223.38,
  "dictionary_match": false,
  "detected_patterns": [
    "predictable_year",
    "common_multiword_phrase"
  ],
  "recommendations": [
    "This passphrase consists of recognizable common words. Consider using less predictable or randomized words.",
    "Avoid appending predictable calendar years (e.g. 2024–2026) to passwords or passphrases."
  ]
}
```

### B. Uncommon, Long Passphrase (`krypton-xylophone-quartz-zenith-8351!`)
*Shows that high-entropy passphrases with uncommon words are preserved and awarded maximum strength:*

```json
{
  "strength": "VERY_STRONG",
  "score": 100,
  "length": 37,
  "character_diversity": 4,
  "character_categories": {
    "lowercase": true,
    "uppercase": false,
    "digits": true,
    "symbols": true
  },
  "shannon_entropy_bits": 149.77,
  "estimated_pool_entropy_bits": 223.31,
  "dictionary_match": false,
  "detected_patterns": [],
  "recommendations": [
    "Add uppercase letters (A-Z).",
    "Your password demonstrates strong length, character diversity, and high unpredictability."
  ]
}
```

### C. Word + Separator + Year (`Password-2026!`)

```json
{
  "strength": "WEAK",
  "score": 35,
  "length": 14,
  "character_diversity": 4,
  "character_categories": {
    "lowercase": true,
    "uppercase": true,
    "digits": true,
    "symbols": true
  },
  "shannon_entropy_bits": 49.30,
  "estimated_pool_entropy_bits": 91.98,
  "dictionary_match": false,
  "detected_patterns": [
    "predictable_year",
    "word_number_combination"
  ],
  "recommendations": [
    "Avoid appending predictable calendar years (e.g. 2024–2026) to passwords or passphrases.",
    "Avoid simple word-plus-number patterns (e.g., Password123 or Tiger99)."
  ]
}
```

---

## 7. Viva Questions and Answers (Academic / College Defense)

### Q1: Why was `Correct-Horse-Battery-Staple-2026!` adjusted from `VERY_STRONG` (100) to `STRONG` (65)?
**Answer:** While long and diverse, `correct horse battery staple` is a widely known passphrase structure originally popularized by XKCD, and `2026` is a predictable calendar year suffix. Attackers configure dictionary and combinator tools to target dictionary words separated by hyphens and suffixed with current years. CyberShield's multi-signal engine detects the common multiword components and predictable year pattern, preventing it from receiving the highest security rating.

### Q2: Does CyberShield penalize all long passphrases?
**Answer:** No. Passphrases constructed using uncommon or random words (such as `"krypton-xylophone-quartz-zenith-8351!"`) do not match common dictionary lists or predictable patterns and achieve `VERY_STRONG` with a score of 100. CyberShield only penalizes passphrases that rely on recognizable common words and predictable calendar structures.

### Q3: What is the mathematical assumption behind multiplying Shannon entropy by password length?
**Answer:** Multiplying empirical per-character Shannon entropy $H(X)$ by length $L$ assumes that the characters are independent and identically distributed (i.i.d.) draws from that empirical distribution. In reality, human passwords violate the i.i.d. assumption because letters form language n-grams and syllables. Therefore, Shannon entropy measures internal character variety, not resistance against dictionary attacks.

### Q4: Why is theoretical character pool entropy ($L \times \log_2(R)$) an upper bound rather than a guarantee?
**Answer:** Pool entropy assumes an exhaustive brute-force attack where every combination in $R^L$ is tested with equal probability. Modern password cracking tools (like Hashcat and John the Ripper) use rule-based transforms, dictionaries, and probabilistic modeling. If a password uses common dictionary words or predictable patterns, the effective search space is orders of magnitude smaller than $R^L$.
