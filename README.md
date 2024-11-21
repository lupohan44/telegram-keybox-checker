# Keybox Checker Telegram Bot in Python

This Telegram bot allows users to check keybox files (```.xml```) by simply sending them to the bot. The bot processes the keybox file and returns the validation results directly in the chat. This project is based on [KeyboxCheckerPython](https://github.com/SenyxLois/KeyboxCheckerPython) and is intended for educational and research purposes.

## First Time Setup

### Prerequisites

- **Python 3.7 or higher** installed on your computer.
- A **Telegram bot token** obtained from [@BotFather](https://t.me/BotFather).
- The required **PEM files** (`google.pem`, `aosp_ec.pem`, `aosp_rsa.pem`, `knox.pem`) placed in the ```lib/pem/``` directory.

### Steps

1. **Clone the repository** into your directory.

   ```bash
   git clone git@github.com:lupohan44/telegram-keybox-checker.git
   ```

2. **Navigate to the project directory**.

   ```bash
   cd telegram-keybox-checker
   ```

3. **Install all required dependencies**.

   > **Tip:** Using a Python virtual environment is highly recommended!

   ```bash
   pip install -r requirements.txt
   ```

   If you're using **Termux** and encounter issues with ```cryptography``` and ```pip```, install the packages using:

   ```bash
   pkg install openssl
   pkg install rust
   export RUSTFLAGS=" -C lto=no" && export CARGO_BUILD_TARGET="$(rustc -vV | sed -n 's|host: ||p')" && pip install cryptography aiohttp python-telegram-bot
   ```

4. **Replace the bot token** in the `config.json` file.

    When first time running the bot, the script will create a `config.json` file in the root directory.

   Open config.json` and set the token you received from BotFather.

   ```json
   {
       "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
   }
   ```

5. **Ensure the PEM files are in place**.

   Place the following PEM files in the ```lib/pem/``` directory relative to your script:

    - ```google.pem```
    - ```aosp_ec.pem```
    - ```aosp_rsa.pem```
    - ```knox.pem```

   These files are required for root certificate validation.

## Usage

1. **Start the bot**.

   ```bash
   python bot.py
   ```

2. **Interact with the bot**.

    - Open Telegram and search for your bot by its username.
    - Start a conversation with the bot by clicking **Start** or sending ```/start```.
    - Send a keybox file (`.xml`) to the bot.
    - The bot will process the file and reply with the validation results.

## Example

*Example of sending a keybox file and receiving a response:*

```
User: *Sends keybox.xml file*

Bot:
Keybox SN: 123456789abcdef
Cert SN: abcdef1234567890
Status: Valid (Google Hardware Attestation)
Keychain: Valid
Validity: Valid (Valid from 2023-01-01 00:00:00 to 2024-01-01 00:00:00)
Root Cert: Google Hardware Attestation
Check Time: 2023-10-01 12:34:56
```

## Example Bot

**You should never trust a public hosted bot, since you do not know whether the bot will save the keybox file, including this example bot. You should always host your own bot**

**This bot is for demonstration purposes only. It might be discontinued at any time without notice.**

Telegram Bot: [@keybox_checker_demo_bot](https://t.me/keybox_checker_demo_bot)

## Commands

- ```/start``` - Start the bot and receive a welcome message.
- ```/help``` - Get information on how to use the bot.

## Special Thanks To

- [KimmyXYC](https://github.com/KimmyXYC/KeyboxChecker) | For the original Keybox checker logic.
- [SenyxLois](https://github.com/SenyxLois/KeyboxCheckerPython) | For the base code and inspiration.
- Hollowed Citra | For providing keyboxes to fix an error that we didn't even know existed.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
