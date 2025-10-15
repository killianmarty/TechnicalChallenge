# Technical Challenge

## Introduction

This project was made for a technical challenge. The goal was to create a simple API calling VirusTotal API for checking reputation of an URL.

## Features

This API server exposes a `/analyze` `POST` endpoint that takes an URL in the body and uses the VirusTotal API to check the URL and get a summary of its reputation. It also logs the server activity for monitoring and troubleshooting.

## Installation

First, clone the repository and install dependencies (virtual environment is optional):

```bash
git clone https://github.com/killianmarty/TechnicalChallenge
cd TechnicalChallenge
python3 -m venv .
source bin/activate
pip install -r requirements.txt
```

Create a `.env` file with theses values:

```env
LOG_FILE = <LOG_FILE>       #(Optional) default "api.log"
PORT = <PORT>               #(Optional) default 8080
API_URL = <BASE_API_URL>    #(Optional) default "https://www.virustotal.com/api/v3"
API_KEY = <API_KEY>         #Required
```

## Usage

Run the API server:

```bash
python3 server.py
```

Make a `POST` API call to `http://localhost:<PORT>/analyze` with the following body and the `Content-Type: application/json` header:

```json
{
    "url": "<YOUR_URL>"
}
```

## Credits

This project was made by Killian Marty.