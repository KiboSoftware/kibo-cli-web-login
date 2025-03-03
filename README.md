# kibo-cli-web-login

A simple npm package to authenticate to Kibo via web login.

## Features

- Generates RSA key pairs for secure communication.
- Decrypts large payloads using RSA and AES.
- Opens a browser window to complete the web login.
- Provides a formatted HTML confirmation for both success and error scenarios.

## Installation

1. Clone the repository.
2. Run `npm install` to install dependencies (including [open](https://www.npmjs.com/package/open)).

## Usage

Require the module and call the `authenticate` method with a `loginUrl`:

