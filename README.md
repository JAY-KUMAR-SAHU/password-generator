# 🔐 Password Generator

A simple, privacy-friendly password generator that runs entirely in your browser.

**Live site:** https://jks-password-generator.netlify.app

## Features

- Choose the password length (8–128) and the minimum number of lowercase, uppercase, numbers and symbols
- Cryptographically secure randomness (`crypto.getRandomValues`)
- Estimated time to crack, with a strength rating
- One-click copy
- Light and dark mode
- Works offline: no server, no tracking, no external requests

## Usage

Use it online at [jks-password-generator.netlify.app](https://jks-password-generator.netlify.app), or open `index.html` in any modern browser. There's nothing to install or build.

## Project structure

| File            | Purpose                                           |
| --------------- | ------------------------------------------------- |
| `index.html`    | Page structure                                    |
| `style.css`     | Styling and light/dark themes                     |
| `script.js`     | Password generation, validation, strength meter   |
| `theme-init.js` | Applies the saved theme before the page appears   |

## How the strength estimate works

The app counts every password possible with your settings. It assumes a powerful offline attack at 100 billion guesses per second, and that the attacker finds the password after trying half the possibilities on average. It's an estimate for randomly generated passwords only.

## Disclaimer

This is a personal project built for learning purposes. It is provided as-is, without any warranty. Use generated passwords at your own discretion.

## License

[Apache 2.0](LICENSE)
