# secret-scanner

A command line tool that walks a codebase looking for hardcoded secrets: AWS
credentials, GitHub tokens, private keys, API keys, and anything else that
looks like it was pasted in and forgotten about.

It uses two detectors that cover each other's blind spots:

1. **Regex patterns** for credential formats that have a recognizable shape
   (`AKIA...`, `ghp_...`, `-----BEGIN RSA PRIVATE KEY-----`).
2. **Shannon entropy analysis** for the ones that do not. A random 32 character
   session key has no distinctive prefix, so no pattern will ever catch it, but
   it is measurably more random than the code around it.

No third party dependencies. Standard library only, Python 3.8+.

## Install

Clone it and run it in place:

```bash
git clone https://github.com/carlmasters02/secret-scanner.git
cd secret-scanner
python3 -m secretscanner .
```

Or install it so the `secret-scanner` command is on your path:

```bash
pip install -e .
secret-scanner .
```

## Usage

```
secret-scanner [-h] [--json] [--history] [--max-commits N]
               [--min-confidence {low,medium,high}] [--no-entropy]
               [--show-secrets] [--no-gitignore] [--version]
               path
```

Scan the current project:

```bash
secret-scanner .
```

```
src/config.py
  line 3     HIGH   aws_access_key_id
      AKIA...MPLE
  line 4     HIGH   aws_secret_access_key
      wJal...EKEY
  line 6     MEDIUM generic_secret_assignment
      kJ8d...uI3o

----------------------------------------------------
3 findings in 1 file (24 scanned)
  high: 2   medium: 1   low: 0
  values are masked, pass --show-secrets to see them
```

Scan one file:

```bash
secret-scanner src/config.py
```

Only show the findings worth waking someone up for:

```bash
secret-scanner . --min-confidence high
```

Turn off entropy analysis when the noise is not worth it:

```bash
secret-scanner . --no-entropy
```

### Scanning git history

Deleting a secret from a file does not remove it from the repository. It is
still in whatever commit added it, and anyone who clones the repo still gets
it. `--history` looks there instead of at the working tree:

```bash
secret-scanner . --history
```

```
app.py
  line 2     HIGH   aws_access_key_id
      AKIA...MPLE
      introduced in commit 0fffa3d91a

----------------------------------------------------
1 finding in 1 file (3 commits scanned)
  high: 1   medium: 0   low: 0
```

It runs `git log --all -p -U0` and scans the lines each commit added, so it
covers every branch and not just the one checked out. Use `--max-commits N` to
limit how far back it goes (the default is 500, since old repos can produce a
lot of patch text).

If the same secret was added in more than one commit it is reported once,
attributed to the earliest commit that introduced it.

Machine readable output:

```bash
secret-scanner . --json
```

```json
{
  "files_scanned": 24,
  "findings_count": 1,
  "summary": { "high": 1, "medium": 0, "low": 0 },
  "masked": true,
  "findings": [
    {
      "file": "src/config.py",
      "line": 3,
      "type": "aws_access_key_id",
      "confidence": "high",
      "match": "AKIA...MPLE"
    }
  ]
}
```

Pipe it into `jq` to pull out just the high confidence hits:

```bash
secret-scanner . --json | jq '.findings[] | select(.confidence == "high")'
```

Matched values are masked by default so a report can be pasted into a ticket
without leaking the thing you are reporting. Use `--show-secrets` if you
actually need to see them.

### Exit codes

| Code | Meaning |
| ---- | ------- |
| 0    | nothing found |
| 1    | at least one finding |
| 2    | bad path or other error |

That makes it usable as a CI gate:

```bash
secret-scanner . --min-confidence high || exit 1
```

## What it looks for

| Type | Confidence |
| ---- | ---------- |
| AWS access key id (`AKIA`, `ASIA`, ...) | high |
| AWS secret access key | high |
| GitHub token (`ghp_`, `gho_`, `ghs_`, ...) | high |
| GitHub fine grained PAT | high |
| Slack token and webhook URL | high |
| Google API key (`AIza...`) | high |
| Stripe live key (`sk_live_`, `rk_live_`) | high |
| OpenAI API key | high |
| npm token | high |
| Private key headers (RSA, DSA, EC, OpenSSH, PGP) | high |
| JWT | medium |
| Credentials embedded in a URL | medium |
| Generic `api_key = "..."` assignments | medium |
| High entropy base64 or hex tokens | medium or low |

Confidence reflects how easy the format is to fake. `AKIA` followed by 16
uppercase characters is almost certainly an AWS key. A string assigned to a
variable called `password` might be a real credential or might be
`"changeme"`, so it lands at medium.

## How entropy detection works

Shannon entropy measures how unpredictable a string is, in bits per character.
For a string where each distinct character `c` appears with probability `p(c)`:

```
H = -sum( p(c) * log2(p(c)) )
```

The intuition: if a string uses a few characters over and over, you can guess
the next character easily and entropy is low. If it uses its whole alphabet
evenly, every character is a surprise and entropy is high.

A few examples:

| String | Entropy | Why |
| ------ | ------- | --- |
| `aaaaaaaa` | 0.00 | one symbol, zero surprise |
| `abcd` | 2.00 | 4 symbols used evenly, log2(4) = 2 |
| `password123` | 3.28 | some repetition, real letters |
| `kJ8dR2mQzXvW9pLcYtNbF4gHs7aEuI3o` | 5.00 | random, uses the alphabet evenly |

The ceiling depends on the character set. Base64 has 64 symbols, so it tops out
at log2(64) = 6 bits per character. Hex has 16, so it tops out at 4. The
thresholds are set below each ceiling, at **4.5 for base64** and **3.0 for
hex**, which separates real keys from ordinary identifiers without much overlap.

The scan works like this:

1. Split each line on characters that do not appear inside credentials.
2. Throw away tokens shorter than 20 characters. Short strings score
   unreliably, and a 12 character token has too few samples for the frequency
   count to mean anything.
3. Work out whether the token is hex, base64, or neither. Neither means skip.
4. Score it and compare against that character set's threshold.

Entropy alone produces false positives, so a few filters run on top:

- **Word shaped tokens are dropped.** `calculate_total_order_price` is long and
  uses many distinct characters, but it is built out of real words. Tokens
  split into several short chunks by `_` or `-` get dropped, as do tokens whose
  vowel ratio is above 0.34. Random strings sit near 0.19 (5 vowels out of 26
  letters); English is closer to 0.40.
- **Hash context is dropped.** Lines mentioning `sha256`, `integrity`,
  `checksum`, `commit`, `uuid` and friends are skipped entirely. Lockfile
  hashes and git SHAs are maximally random and never secrets.
- **Regex wins ties.** If a pattern already claimed a value, it is not reported
  a second time as a high entropy token.
- **Confidence scales with the score.** Tokens more than 0.4 bits above the
  threshold are medium, the rest are low.

This is the same general approach truffleHog popularized. It will not catch a
secret that happens to be a dictionary word, and it will occasionally flag a
long random string that is not a secret. It is a smoke alarm, not a proof.

## Ignoring files

`.gitignore` is respected by default. Pass `--no-gitignore` to scan everything.

Supported: comments and blank lines, plain names, globs like `*.env`, directory
patterns like `build/`, patterns anchored with a leading slash like
`/config.py`, patterns containing a slash like `src/generated.py`, `!`
exceptions, and nested `.gitignore` files applying to their own subtree.

Not supported: `**` for matching across directories, character ranges like
`[abc]`, and git's full rule ordering (a later rule overriding an earlier one).
Exceptions are checked before ignore rules instead, which gives the same answer
for ordinary files and errs toward scanning a file rather than skipping it. For
a tool whose job is finding secrets, scanning too much is the safer mistake.

`tests/test_scanner.py` checks the walker against git itself: it builds a repo,
asks `git add --dry-run` which files it would track, and asserts the walker
reaches the same set.

Some things are always skipped regardless: `.git`, `node_modules`, `venv`,
`__pycache__` and similar directories, binary and media files, files over 2 MB,
and lines longer than 500 characters (minified JS is not worth scanning).

## Running the tests

```bash
pip install pytest
python3 -m pytest
```

## Limitations

Worth knowing before trusting it:

- Every check is line by line, so a private key body split across lines is
  detected by its header only.
- The generic assignment pattern is deliberately broad and will flag test
  fixtures and example config.
- Entropy detection cannot catch a weak secret. `password123` is a terrible
  credential and scores far too low to be flagged.
