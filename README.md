# 🛡️ Scam Slayer — UPI Safety Coach

A small web app that helps students and families in India check a suspicious UPI situation.
Describe what happened in your own words and get a clear card: a **verdict badge**
(SCAM / SUSPICIOUS / LIKELY SAFE / NOT SURE / INFO), the **reason**, the **red flags**,
**what to do**, and the **source**.

* 15 built-in scam patterns (collect requests, QR scams, fake KYC/OTP calls, "digital arrest", job and investment scams ...) answer instantly with no AI.
* Anything the library is not sure about goes to an AI (Groq). The server makes the AI answer in the same card format, with emojis, and a separate source line.
* A 10-question before/after safety quiz, a printable WhatsApp safety poster, and a team results page.

## Privacy and safety
* The server **refuses** any message that contains a PIN, OTP, password, card/account number or phone number — it never reaches the AI.
* **No chat text is stored.** Only anonymous counts are saved (which scenario matched) and quiz scores under a first name or "User 1".
* The AI key stays on the server. It is never sent to the browser.
* The app gives general awareness advice (based on RBI, NPCI and cyber-police material). It is not legal or banking advice. **If money is lost, call 1930 and report at cybercrime.gov.in.**

## Files
| File | What it is |
|---|---|
| `app.py` | Flask backend: serves the page, talks to the AI, safety guard, rate limits, quiz data, team results |
| `index.html` | The whole web app (one file, works on phones, tablets and computers) |
| `a.env.example` | Template for your settings. Copy it to `a.env` |
| `requirements.txt` | Python packages |
| `Procfile`, `render.yaml` | Ready-made settings for hosting (Render / Railway) |
| `.gitignore` | Keeps your secrets and test data out of GitHub |

## Run it on your computer
```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp a.env.example a.env            # Windows: copy a.env.example a.env
# open a.env and paste your Groq key and a long ADMIN_KEY
python app.py
```
Open http://127.0.0.1:5004 . To let phones on the same Wi-Fi open it, set `HOST=0.0.0.0` in `a.env` and use the address that the terminal prints.

## Put it on the internet (GitHub stores the code, Render runs it)
GitHub (and GitHub Pages) cannot run a Python backend, so use a free host such as Render:

1. Push this folder to a GitHub repository (steps below).
2. On https://render.com choose **New + → Blueprint**, connect your GitHub and pick the repo. Render reads `render.yaml`.
3. When asked, type your **`GROQ_API_KEY`** and a long random **`ADMIN_KEY`** into Render's form (never into GitHub).
4. Deploy. Your app gets a public `https://…onrender.com` link.

Notes for the free plan: the app sleeps after some idle time (the first visit takes ~30 seconds to wake it), and its disk is erased on each redeploy, so quiz data does not survive. Add a Render disk and set `DATA_DIR` to it, or download the results from `/api/export.csv` regularly (send the `X-Admin-Key` header).
Railway works too: it uses the `Procfile`; add the same variables in its Variables tab and set `TRUST_PROXY=true`.

## Publish to GitHub
```bash
git init
git add .
git status        # CHECK: a.env must NOT be in this list
git commit -m "Scam Slayer: UPI safety coach"
git branch -M main
git remote add origin https://github.com/<your-username>/scam-slayer.git
git push -u origin main
```
**Never commit `a.env`.** If a key was ever pushed or shared, delete it at https://console.groq.com/keys and create a new one — removing the file later does not remove it from git history.

## The poster link (admin only)
The website link on the poster is locked for visitors. It comes from the server: set `POSTER_URL=https://your-app.onrender.com` in `a.env` (or Render's Environment tab). If you leave it unset, the site's own address is used. To change it for one poster without editing settings, open the Poster page, click **Admin: change link** and enter your `ADMIN_KEY`.

## Team results (10-day test)
Set `ADMIN_KEY`, then call `/api/stats` (summary) or `/api/export.csv` (every quiz result for Excel/Sheets) with the header `X-Admin-Key: <your key>`. The web app has a Team results page that asks for the same key.

## Credits
Brand font: Oxanium ExtraBold (SIL Open Font License), embedded in `index.html`.
