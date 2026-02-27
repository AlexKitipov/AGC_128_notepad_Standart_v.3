# AGC_128_notepad_Standart_v.3
AGC_128_Standart_notepad_v.3 is a unified reversible text‑to‑DNA encoding system supporting ASCII and Unicode (UTF‑8). It offers full bidirectional conversion, FASTA compatibility, genetic integrity checks, and a lightweight tkinter GUI for editing, encoding, and decoding sequences.

# AGC_128_Standart_notepad_v.3 — Adaptive Genetic Code 128 (Unified Edition)

## Official README (Unified Edition)

---

## Authors
- **Aleksandar Kitipov**  
  Emails: aeksandar.kitipov@gmail.com / aeksandar.kitipov@outlook.com  
- **Copilot**  
  Co‑author, technical collaborator, documentation support
  - **Gemini 2.5 Flash**  
  Co‑author, technical collaborator, documentation support

---

## 1. Overview
**AGC_128_Standart_notepad_v.3** is the unified and enhanced version of the Adaptive Genetic Code 128 text encoding system. It combines the original **v.1 (ASCII)** capabilities with the **v.2 (Unicode)** extension, offering a robust, fully reversible, DNA-inspired encoding solution for both basic ASCII text and the entire Unicode character set.

This version features an interactive Graphical User Interface (GUI) built with `tkinter`, allowing users to seamlessly switch between v1 and v2 encoding/decoding, open/save text files, encode to/decode from FASTA files, and manage genetic checksums. Like its predecessors, it requires **no external libraries** for its core encoding/decoding logic, maintaining a tiny footprint while ensuring high data integrity through its self-checking genetic structure.

---

## 2. What the Program Does

AGC_128_Standart_notepad_v.3 provides complete reversible transformations:

### v.1 (ASCII) Transformation:
```
Text → ASCII (8 bits) → 4 (2-bit genes) → A/T/G/C DNA Sequence
```
And back:
```
DNA Sequence → 4 (2-bit genes) → 8-bit ASCII → Text
```

### v.2 (Unicode) Transformation:
```
Unicode Text → UTF-8 Bytes → Length Gene + Genetic Bytes → A/T/G/C DNA Sequence
```
And back:
```
DNA Sequence → Genetic Bytes + Length Gene → UTF-8 Bytes → Unicode Text
```

This system precisely preserves:
- **v.1:** Letters, numbers, punctuation, whitespace, and ASCII extended symbols.
- **v.2:** Any Unicode character (including ASCII, Cyrillic, CJK, Emojis, Symbols), preserving structured blocks and FASTA-formatted sequences.

**If you encode text and decode it again using the correct version, the output will match the original exactly, character-for-character, byte-for-byte.**

---

## 3. Key Features

### 3.1. Unified Encoding/Decoding
Supports both `v1 (ASCII)` for lightweight, fixed-length encoding of standard ASCII characters and `v2 (Unicode)` for comprehensive variable-length encoding of all Unicode characters via UTF-8.

### 3.2. Intuitive Graphical User Interface (GUI)
Built with `tkinter` for ease of use, featuring:
- **Version Selection:** Radio buttons to choose between `v1 (ASCII)` and `v2 (Unicode)` encoding/decoding modes.
- **File Operations:** Open, Save, Save As, and New file functionalities.
- **Edit Menu:** Standard text editor actions like Undo, Redo, Cut, Copy, Paste, Delete, and Select All.
- **Context Menu:** Right-click menu for quick editing actions.
- **FASTA Management:** Encode current text to FASTA and Load/Decode FASTA files.
- **Checksum Integration:** Options to add, verify, and consider genetic checksums during encoding/decoding.
- **Visualization Placeholder:** Provides basic sequence information.

### 3.3. Full Reversibility
Every character, whether ASCII or Unicode, is transformed reversibly, ensuring zero data loss upon decoding.

### 3.4. Self-Checking Genetic Structure (Inherited from v1 & v2)
AGC-128 maintains its three core biological-style integrity rules:
- **Sum-2 Rule**: Each 2-bit gene has a total bit-sum of 2. Any bit flip breaks the rule and becomes detectable.
- **No-Triple Rule**: The sequence can never contain `111` or `000`. If such a pattern appears, the data is invalid.
- **Deterministic-Next-Bit Rule**: Predictable bit sequences (`11` → `0`, `00` → `1`). This allows partial reconstruction of missing or damaged data.

### 3.5. FASTA Compatibility
The DNA output can be saved as a `.fasta` file, making it suitable for digital archiving, DNA-like storage experiments, and bioinformatics-style workflows.

---

## 4. Genetic Alphabet
AGC-128 uses four genetic symbols mapped from 2-bit pairs:

```
11 → G  
00 → C  
10 → A  
01 → T
```

---

## 5. AGC-128 v2 (Unicode) Core Principles in Detail

### 5.1. UTF-8 as Foundation
Unicode characters are first converted to their UTF-8 byte representation (1 to 4 bytes).

### 5.2. Length Prefix Gene
Each encoded Unicode character begins with a single-nucleotide `Length Gene` that indicates the number of UTF-8 bytes that follow for that character:

| UTF-8 Length | Number of Bytes | 2-bit Marker | Length Gene |
|--------------|-----------------|--------------|-------------|
| 1 byte       | ASCII           | 00           | C           |
| 2 bytes      | Cyrillic        | 01           | T           |
| 3 bytes      | Multi-byte      | 10           | A           |
| 4 bytes      | Emojis          | 11           | G           |

### 5.3. Byte Encoding
Each individual UTF-8 byte (0-255) is encoded into four 2-bit nucleotide genes, consistent with AGC-128 v1's 8-bit to 4-nucleotide conversion.

Thus, a Unicode character's genetic sequence is: `[Length Gene] + [4 genes per byte]`.
- **1-byte UTF-8 (ASCII)** → `C` + 4 genes = 5 nucleotides
- **2-bytes UTF-8 (e.g., Cyrillic)** → `T` + 8 genes = 9 nucleotides
- **3-bytes UTF-8 (e.g., Chinese)** → `A` + 12 genes = 13 nucleotides
- **4-bytes UTF-8 (e.g., Emojis)** → `G` + 16 genes = 17 nucleotides

---

## 6. Genetic Checksum
An optional 2-nucleotide genetic checksum can be appended to the entire sequence to verify data integrity. It calculates the sum of all 2-bit nucleotide values, modulo 16, and encodes this 4-bit result into two nucleotides. The GUI provides explicit options to add and verify this checksum, ensuring flexibility and data validation.

---

## 7. Usage (GUI)

To use the GUI:
1. **Run the script locally** (as `tkinter` requires a graphical environment).
2. **Select Encoding/Decoding Version:** Use the radio buttons (`v1 (ASCII)` or `v2 (Unicode)`).
3. **Type or Load Text:** Enter text directly or use `File > Open`.
4. **Encode to FASTA:** Go to `Encode > Encode to AGC-128 FASTA`. You'll be prompted for a FASTA header and whether to add a checksum.
5. **Load and Decode FASTA:** Go to `Decode > Load and Decode AGC-128 FASTA`. The system will prompt if a checksum is expected and verify it if present.
6. **Tools:** `Verify Checksum` (for currently loaded sequence) and `Visualize Sequence` (placeholder info).

---

## 8. Command-Line Usage (Colab Environment)

When running in environments without a GUI (like Google Colab), the script automatically executes example encoding/decoding functions for both v1 and v2, demonstrating core functionality.

**Example Output in Colab:**
```
Running in Google Colab environment. Tkinter GUI cannot be displayed.

Here's an example of how to use the core encoding/decoding functions directly:

Original Text (V2 Unicode): Здравейте, свят!😊 123
Encoded (V2 Unicode): TGTCCA TTGTCCAGTC TGTC TACCCTGTCCAGCCC TTGTCCAGCATGTCCAGTTTGTC ... (Total: 73 nucleotides)
Encoded with Checksum (V2 Unicode): TGTCCA TTGTCCAGTC TGTC TACCCTGTCCAGCCC TTGTCCAGCATGTCCAGTTTGTC ... (Total: 75 nucleotides)
Checksum for V2 is valid: True
Decoded (V2 Unicode): Здравейте, свят!😊 123
V2 Encoding/Decoding successful: True

---

Original ASCII Text (V1 ASCII): Hello, Colab!
Encoded (V1 ASCII): TCACTATTTAGCTAGCAGGCA CCTCC TGGTAGCTACTACACACT
Encoded with Checksum (V1 ASCII): TCACTATTTAGCTAGCAGGCA CCTCC TGGTAGCTACTACACACTCG
Checksum for V1 is valid: True
Decoded (V1 ASCII): Hello, Colab!
V1 Encoding/Decoding successful: True
```

---

## 9. Project Status
- **AGC_128_Standart_notepad_v.3** — Stable unified core with GUI.

---

## 10. Notes
This README represents the comprehensive documentation for the unified AGC-128 Notepad, incorporating all features and improvements developed through collaborative discussions and testing.
