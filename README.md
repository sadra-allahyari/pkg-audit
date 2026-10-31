# pkg-audit

Independent check that package and container **mirrors** serve what the official source serves.

[فارسی](#فارسی)

A mirror is trusted by every client that points at it. Docker, for one, pulls `alpine:3.20` from a
mirror and checks no publisher signature: it trusts the digest the mirror names. npm, PyPI, Cargo
and Maven take their hashes from the mirror too. So a compromised mirror (or insider) can serve
altered content with a matching hash, and the client cannot tell. `pkg-audit` asks the official
source and each mirror the same question and reports any difference. It needs nothing but Python 3.8+
(standard library only) and runs well as an hourly CI job on a machine **outside** the mirrors'
network.

## What it compares

| Ecosystem | Value compared with the official source |
| --- | --- |
| Docker | digest of each tag (and that the manifest hashes to it); a different digest Docker Hub still serves is `stale`, any other is `mismatch` |
| npm | `dist.integrity` of a pinned version |
| PyPI | sha256 of every file of a pinned version (JSON or HTML index) |
| Cargo | `cksum` in the sparse index |
| Maven | `.jar.sha1` |
| RubyGems | `checksum` in the compact index |
| Node.js, Go, Gradle, Helm, kubectl, HashiCorp | the checksum file of a pinned release |

Packages are pinned to a version, so metadata is immutable and any difference is a `mismatch`.
Files themselves are not downloaded: equal hashes mean equal content, and a client verifies the
file against that hash.

## Use

```bash
python3 pkg_audit.py examples/images.txt examples/docker-mirrors.txt \
  --packages examples/packages.txt --targets examples/targets.txt \
  --brand examples/brand.json --json site/report.json --html site/index.html
```

### Spread the checks over the hour

A full run is a few hundred requests to dozens of hosts. Instead of all at once, run the job every
few minutes and let each run check only its share:

```bash
python3 pkg_audit.py ... --state site/report.json --json site/report.json \
  --slots 12 --slot-minutes 5     # cron: */5 * * * *  -> every host once an hour
```

- `--slots N` spreads the hosts evenly over N runs; the turn comes from the clock (`--slot-minutes`
  is how often the job runs), or force one with `--slot I`.
- `--state` is the previous `report.json`. A mirror that is not checked in this run keeps its last
  result and its time (the page shows "last checked HH:MM"), until its turn comes.
- A mirror with no earlier result (new, changed URL, new items) is checked at once.
- Only the official sources needed by this run's mirrors are asked.
- `--workers N` (default 6) hosts are checked at the same time, but a host never gets more than one
  request at a time, however many ecosystems it serves.

### Let visitors ask for a re-check

`serve.py` serves the page and takes re-check requests (standard library only):

```bash
python3 serve.py --site site --queue queue.json --cooldown 30 --port 8080
python3 pkg_audit.py ... --queue queue.json --state site/report.json ...   # in the CI job
```

Set `"recheck_minutes": 30` in `brand.json` and every mirror gets a "request a re-check" button.
A request goes into `queue.json`; the next job run checks that mirror whatever its turn is and
removes it from the queue, and the page marks it "in the queue" until then.

Abuse is bounded on the server, not in the page: only a (group, mirror) pair that is in
`report.json` can be queued (never an address a visitor types); a mirror checked less than
`--cooldown` minutes ago, by anyone, is refused with the minutes left; a pair already queued is not
added again; and there is a small per-client rate limit. No access log, no cookies.

Exit status is 2 when any `mismatch` is found, so a CI job fails and notifies. Copy `assets/*` next
to `index.html` (font and icon the page references). `examples/` has the list formats and a GitLab
CI job; pin the commit of this repository you reviewed.

## What a green result does not prove

- That the auditor got a correct answer, not that every client, at every time, does. A mirror that
  answers the auditor honestly and other addresses (or an outage window) differently is not seen.
  Run from several networks, inside and outside, and probe each PoP with the pinned address option.
- That the official source is itself uncompromised.
- Anything about packages that are not in your lists.

Pin hashes in your own builds regardless: lockfiles with integrity hashes, `pip --require-hashes`,
`distributionSha256Sum`, and `image@sha256:…`. Then no mirror can serve other content.

Host names in a list are only labels; which company operates a mirror is theirs to confirm.
Mirrors that need an account or credit to answer are left out.

## Test

```bash
python3 tests/test_pkg_audit.py
```

## License

Apache-2.0 (see `LICENSE`). The bundled font Vazirmatn is under the SIL Open Font License
(`assets/OFL-Vazirmatn.txt`).

---

## فارسی

بازرسی مستقل برای اینکه **میرورهای** بسته و ایمیج همان چیزی را می‌دهند که منبع رسمی می‌دهد.

هر کلاینتی که به یک میرور وصل شود به آن اعتماد می‌کند. Docker با `docker pull .../alpine:3.20` هیچ امضای
ناشری را بررسی نمی‌کند و به digestی که میرور می‌دهد اعتماد می‌کند؛ هش npm و PyPI و Cargo و Maven هم از خود
میرور می‌آید. پس میرور آلوده می‌تواند محتوای دست‌کاری‌شده را با هش مطابقش بدهد و کلاینت تفاوتی نمی‌فهمد.
`pkg-audit` همان سؤال را از منبع رسمی و از هر میرور می‌پرسد و هر تفاوت را گزارش می‌کند. فقط Python 3.8+
می‌خواهد و بهتر است ساعتی در CI، روی ماشینی **بیرون از شبکه‌ی میرورها** اجرا شود.

- ایمیج‌های Docker، هش npm، فایل‌های PyPI، `cksum` در Cargo، `sha1` در Maven، checksum در RubyGems و
  فایل checksum نصب‌کننده‌ها (Node.js، Go، Gradle، Helm، kubectl، HashiCorp) بررسی می‌شوند.
- بسته‌ها روی نسخه‌ی ثابت سنجیده می‌شوند، پس هر تفاوتی `mismatch` است. فایل‌ها دانلود نمی‌شوند.
- سبز یعنی بازرس جواب درست گرفته، نه اینکه همه‌ی کاربران همیشه همین را می‌گیرند. حمله‌ی مخصوص بعضی
  نشانی‌ها یا زمان قطعی اینترنت دیده نمی‌شود.
- برای پروژه‌های حساس هش را خودتان ثابت کنید (lockfile با هش، `--require-hashes`، `image@sha256:…`).

اجرا و قالب فایل‌ها در `examples/` است. لایسنس: Apache-2.0.
