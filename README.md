I shipped **Clikk** — a Chrome extension that detects phishing and malicious links **before you click**, with the ML model running entirely on your device.

It's now live on the Chrome Web Store.

The interesting part wasn't building the model. It was discovering how easy it is to fool yourself.

**Attempt #1: SecureBERT**

I fine-tuned SecureBERT on a public URL dataset and got incredible accuracy.

Too incredible.

After digging deeper, I realized the model wasn't learning what makes a URL malicious. It had learned dataset shortcuts—recognizing domains it had already seen instead of understanding URL patterns. Once tested on unseen domains, performance fell apart.

I scrapped it.

Then I audited the datasets themselves.

One popular Kaggle malicious URL dataset (used in countless notebooks) appeared to have its labels swapped. Comparing it against trusted threat feeds showed an almost perfectly symmetric disagreement. Instead of trusting it, I rebuilt the dataset from primary sources: URLhaus, OpenPhish, and ThreatFox.

**Attempt #2: What actually shipped**

Sometimes simple wins.

I trained a **TF-IDF character n-gram (3–5) + Logistic Regression** model because the requirement wasn't leaderboard accuracy—it was running entirely inside a Chrome extension.

The result:
• 98.6% accuracy
• 0.3% false-positive rate
• Domain-grouped evaluation (no domain leakage)

To deploy it, I exported the trained weights into a **1.7 MB JSON** file and rewrote inference from scratch in vanilla JavaScript.

To make sure nothing changed during deployment, I replayed all **5,249 test URLs** through both the Python and JavaScript implementations.

The result:

* Identical predictions
* Identical confusion matrix
* Maximum probability difference: **2×10⁻⁸**
* ~200 μs inference per URL

In production, the extension checks:

1. Local blocklists
2. The on-device ML model
3. VirusTotal only when the model's confidence is below 90%

That means most URLs are classified without ever leaving your device.

The biggest lesson from this project wasn't about machine learning.

It was that the hardest part isn't training a model—it's proving your **model, your data, and your deployment** aren't quietly lying to you.

Chrome Web Store: https://chromewebstore.google.com/detail/ebnadedjcjlnhbdcfogbglecfoimhmom

Code + training pipeline:
https://github.com/vanji-creator/linkguard
