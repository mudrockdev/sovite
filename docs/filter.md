# Filter rules

The filter part (`[stack] filter`) scores messages with rules, the way Rspamd does. Rules find *symbols* in a message, each with a score. The scores add up to the message's score, which will decide what is done with it (the actions come later in 2.0; see [`ROADMAP.md`](../ROADMAP.md)).

Rules are in TOML files named by [`[filter] rules`](configuration.md#filter). `sovitectl config check` reads and checks them, and so does a reload. Changed files are read again without a restart (see `reload_interval`).

## Rule files

A rule file has four kinds of entries. Each has a `name` (letters, digits, and `_`) and an optional `description`.

```toml
[[group]]
name = "headers"
max_score = 6.0          # the group's symbols add at most this much
min_score = -6.0         # and take away at most this much

[[map]]
name = "bad_domains"
type = "domain"
file = "/etc/sovite/maps/bad_domains.txt"

[[symbol]]
name = "SUBJECT_CAPS"
group = "headers"
score = 2.5
description = "The subject is in capitals"
match = "subject"
regex = '\A[^a-z]{12,}\z'

[[symbol]]
name = "URL_BAD_DOMAIN"
score = 6.0
match = "url_host"
map = "bad_domains"
condition = "!is:authenticated"

[[composite]]
name = "CAPS_AND_BAD_URL"
expression = "SUBJECT_CAPS & URL_BAD_DOMAIN"
score = 4.0
```

### `[[symbol]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | name | required | The symbol's name. Symbols and composites share names. |
| `score` | number | `0.0` | What the symbol adds to the message's score; negative to take away. |
| `group` | name | unset | The group it belongs to. Groups that no `[[group]]` describes have no limits. |
| `match` | target | unset | What the rule looks at: see [Targets](#targets). Required with `regex` or `map`. |
| `regex` | string | unset | A regular expression (PCRE, UTF-8, Unicode classes). The symbol matches when it matches one of the values of `match`. Use TOML's literal strings (`'...'`) to keep backslashes as they are. |
| `flags` | string | `""` | Flags of `regex`: `i` (case-insensitive), `m` (`^` and `$` at line ends), `s` (`.` matches newlines), `x` (white space and comments in the pattern ignored). |
| `map` | name | unset | A `[[map]]`. The symbol matches when one of the values of `match` is in it. |
| `condition` | expression | unset | The rule runs only when this holds: see [Expressions](#expressions). It sees the symbols found before it: those found by Sovite's own checks, then the rules above it, in order. |
| `enabled` | boolean | `true` | `false` turns the symbol off. |

A symbol without `regex` or `map` is found by Sovite's own checks (SPF, DKIM, DNS lists, ...): its entry gives it a score and a group.

What a symbol matched (up to three values) is kept with it, for the message trace.

A regular expression may take only so much work on one value, so a pattern that backtracks badly (`(a+)+$`) gives up instead of holding up the scan: it counts as not matching, and the scan notes `match_limit`. A pattern looks at most at the first 1 MiB of a value.

### Targets

| Target | Values |
|---|---|
| `header:<Name>` | Each field of the message named so (case-insensitive), unfolded, with encoded words (`=?utf-8?B?...?=`) decoded. |
| `raw_header:<Name>` | The same, not decoded. |
| `mime_header:<Name>` | The same as `header:`, in every MIME part. |
| `headers` | The whole header section, as it came. |
| `subject` | The subject, decoded. |
| `text` | The text of each text part, HTML made text. |
| `hidden_text` | What HTML parts hide (`display:none`, zero font size, ...). |
| `html` | The source of each HTML part. |
| `body` | The body of the message as it came, not decoded. |
| `url` | The URLs in the text and links, normalized (see below). |
| `url_host` | Their hosts. |
| `address` | The mail addresses in the text. |
| `attachment_name` | Attachments' file names. |
| `attachment_type` | Attachments' types, by their content when it is known (`application/x-msdownload`), else as declared. |
| `attachment_hash` | Attachments' SHA-256 hashes, lower-case hex. |
| `ip`, `hostname`, `helo` | The client's address, its name from reverse DNS, and its `EHLO` name. |
| `from`, `from_domain` | The envelope sender (`MAIL FROM`) and its domain. |
| `rcpt`, `rcpt_domain` | The envelope recipients and their domains. |
| `user` | The user who logged in with `AUTH`. |

URLs are found with a scheme or starting with `www.`, also when written to dodge filters (`hxxp://`, `example[.]com`). Hosts are lower-cased, internationalized names given as `xn--` labels, and IPv4 addresses in other forms (`http://3232235777/`) turned into the usual dotted form. URLs that redirectors carry in their query (`?url=https://...`) are there too.

### `[[map]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | name | required | The map's name, for `map` of a symbol. |
| `type` | `ip` \| `domain` \| `address` \| `string` | required | What it holds. |
| `file` | absolute path | unset | A file with one entry per line. Anything after `#`, and after the first white space of a line, is ignored. Entries that are not valid are left out and logged. |
| `entries` | list of strings | unset | The entries, in the rule file. Give `file` or `entries`. |

- `ip`: addresses and networks, `192.0.2.1` and `2001:db8::/32`.
- `domain`: domains, which match their subdomains too: `example.com` matches `mail.example.com`. A mail address is looked up by its domain.
- `address`: mail addresses, or `@example.com` for every address at a domain.
- `string`: anything else (hashes, `EHLO` names, ...). Compared case-insensitively, like the others.

A map file that changes is read again within `reload_interval`; one that cannot be read keeps what was read before.

### `[[composite]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | name | required | The composite's name. Other composites may use it. |
| `expression` | expression | required | When it holds over the symbols found, the composite matches. |
| `score` | number | `0.0` | What it adds. |
| `group` | name | unset | Its group. |
| `policy` | `remove` \| `remove_weight` \| `leave` | `remove` | What happens to the symbols it names outside a negation: `remove` takes them out, so their scores do not count twice; `remove_weight` keeps them, with no score; `leave` keeps them as they are. |
| `enabled` | boolean | `true` | `false` turns it off. |

### `[[group]]`

| Key | Type | Default | Description |
|---|---|---|---|
| `name` | name | required | The group's name. |
| `max_score` | number | unset | The most its symbols add together. |
| `min_score` | number | unset | The most they take away together (a negative number). |

## Expressions

Composites and conditions are boolean expressions over:

- a symbol's name: it was found;
- `g:name`: a symbol of the group was found; `g+:name`: one with a positive score;
- `is:flag`: the message has the flag: `authenticated` (the sender logged in), `trusted` (from `[smtp] trusted_networks`), `tls`, `inbound` (for a domain of this server), `outbound`.

They combine with `!` (not), `&` (and), `|` (or), and parentheses. `!` binds tightest, then `&`, then `|`: `A & !B | C` is `(A & (!B)) | C`.

Every name must exist: a symbol, composite, or group that is not defined, or a composite that depends on itself, is an error.

## Changing the rules of other files

Entries are merged by name across files, in the order of `[filter] rules`: a later entry changes only the keys it sets. A local file can change a score, or turn a rule off, without copying it:

```toml
[[symbol]]
name = "SUBJECT_CAPS"
score = 4.0

[[symbol]]
name = "URL_BAD_DOMAIN"
enabled = false
```

Within one file, a name may be used once.

## Scoring

The message's score is the sum of its symbols' scores, with each group's share kept within its `max_score` and `min_score`. Symbols that composites remove do not count. The rules for one message may take [`[filter] timeout`](configuration.md#filter); the rules after it do not run.
