# 🔐 Password Strength Analyser & Security Advisor

A smart, client-side password strength analyser that provides real-time feedback and personalised security advice.

## Features

- **Real-time strength scoring** — entropy-based calculation with a 0–100 score
- **Visual strength meter** — color-coded from red (very weak) to green (very strong)
- **Pattern detection** — catches common passwords, keyboard walks, leet speak, repeated/sequential characters, date patterns
- **Crack time estimate** — based on 10 billion guesses/sec (modern GPU cluster)
- **Personalised security advice** — context-aware tips based on detected weaknesses
- **Password generator** — cryptographically secure with configurable options
- **Privacy-first** — everything runs locally in your browser, nothing is sent over the network

## Usage

Open `index.html` in any modern browser. No build step, no dependencies, no server required.

## How It Works

The analyser evaluates passwords across multiple dimensions:

1. **Entropy calculation** — based on character set size and length
2. **Dictionary check** — against a list of commonly breached passwords
3. **Pattern recognition** — keyboard walks (qwerty, asdf), sequential chars (abc, 123), repeated chars
4. **Leet speak detection** — recognises substitutions like p@$$w0rd
5. **Date detection** — flags years and date formats that are easily guessed

## License

MIT
