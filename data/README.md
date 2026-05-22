# Corpus Acquisition

The evaluation harness requires two corpora that are not redistributed in this repository (the malicious corpus is large and the libraries are third-party). Both are publicly obtainable. Reconstruct them as follows.

Target layout:

```
evaluation/eval_corpus/
├── benign_48/          48 production library .js files
└── malicious_1061/     1,061 malicious .js and .html files
```

## Malicious corpus (1,061 samples)

The malicious set is composed of two parts, matching the paper:

1. **Curated 61-sample exploit-kit set**, stratified across JavaScript-obfuscation families (Angler, RIG, Blackhole, and CVE-based exploits), drawn from the public JS-Malicious-Dataset repository.

2. **1,000-sample stratified draw** from the Petrak JavaScript Malware Collection, a public-domain repository of approximately 40,000 JavaScript malware samples spanning 2015 to 2019.

   - Petrak collection: https://github.com/HynekPetrak/javascript-malware-collection

Combine both into `evaluation/eval_corpus/malicious_1061/`. The set contains both `.js` and `.html` files; the harness scores both. Total: 1,061 files (61 curated + 1,000 Petrak).

## Benign corpus (48 libraries)

The benign set is 48 canonical CDN library releases. Download each from cdnjs or unpkg and place in `evaluation/eval_corpus/benign_48/`. The exact files and versions used are:

```
alpine-3.14.3.min.js          anime-3.2.2.min.js
axios-1.7.2.min.js            backbone-1.6.0.min.js
bootstrap-5.3.3.min.js        cannon.js
chart-4.4.1.min.js            codemirror.js
cropperjs.min.js              d3-7.9.0.min.js
dayjs-1.11.10.min.js          dompurify.min.js
fabric.min.js                 fullcalendar.min.js
gsap-3.12.5.min.js            hammer.min.js
handlebars-4.7.8.min.js       highlight-11.9.0.min.js
howler.min.js                 immutable.min.js
jquery-3.7.1.min.js           konva.min.js
leaflet-1.9.4.min.js          lodash-4.17.21.min.js
lottie.min.js                 luxon.min.js
marked-11.1.1.min.js          mathjs.js
matter.min.js                 moment-2.30.1.min.js
p5.min.js                     paper.min.js
pdf-lib.min.js                pixijs.min.js
popper-2.11.8.min.js          prism-1.29.0.min.js
react-18.3.1.production.min.js react-dom-18.3.1.production.min.js
rxjs.min.js                   socket.io-4.7.4.min.js
sortablejs.min.js             sweetalert2-11.10.5.min.js
three-0.160.0.min.js          tone.js
underscore-1.13.6.min.js      videojs.min.js
vue-3.4.15.min.js             zod.js
```

Most are available at `https://cdnjs.cloudflare.com/ajax/libs/<name>/<version>/<file>` or `https://unpkg.com/<package>@<version>/<path>`.

## Verifying the corpora

After placing both corpora, run `python3 calibrate.py` from the `evaluation/` directory. It should report 10 of 48 benign files flagged (20.8% FPR) and 632 of 1,061 malicious files flagged (59.6% TPR) at threshold T=40. If those numbers match, the corpora are correctly assembled and the scorer reproduces the paper's static-evaluation results. If the malicious TPR is lower than expected, check for zero-byte files with `find eval_corpus/malicious_1061 -empty`.
