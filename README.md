{\rtf1\ansi\ansicpg1252\cocoartf2868
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # BSM: Browser Security Monitoring Framework\
\
BSM is a browser-resident security monitoring framework for detecting JavaScript API abuse and prompt-injection style inputs inside the browser runtime.\
\
This repository contains the source code, detection logic, and browser extension configuration used for the BSM research prototype described in our paper.\
\
## Overview\
\
BSM runs as a Chrome Manifest V3 extension. It injects monitoring logic at page start, observes security-relevant browser APIs, and records suspicious behaviors such as:\
\
- `fetch` usage\
- `window.open` usage\
- `eval` invocation\
- prompt-injection indicators entered through browser prompts\
- suspicious keyword, encoding, escape-character, and command-pattern features\
\
The framework maintains runtime telemetry in the page context and exposes an export helper for collecting evaluation data.\
\
## Repository Structure\
\
```text\
.\
\uc0\u9500 \u9472 \u9472  manifest.json       # Chrome Manifest V3 extension configuration\
\uc0\u9500 \u9472 \u9472  background.js       # Background service worker for event aggregation\
\uc0\u9500 \u9472 \u9472  data-store.js       # Content-script data initialization\
\uc0\u9500 \u9472 \u9472  hooks.js            # Injects page-level monitoring logic\
\uc0\u9500 \u9472 \u9472  injected.js         # Main API monitoring and prompt-injection detection logic\
\uc0\u9492 \u9472 \u9472  legacy/             # Older prototype files, if retained}