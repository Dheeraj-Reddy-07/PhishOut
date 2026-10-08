# PhishOut
Hybrid Structural & Semantic Phishing Detection

## Overview

Phishing webpages remain a critical cybersecurity threat, continuously adapting to evade detection. Traditional structural detection models (which analyze URL length, domain randomness, and keywords) are often insufficient because attackers dynamically perturb webpage paths to appear benign. On the other hand, complex legitimate URLs—such as nested authentications, payment gateways, and deep nested queries—frequently trigger false positives. 

PhishOut introduces a robust solution: a **Hybrid Structural and Semantic Phishing Detection** engine. It analyzes low-level structural URL characteristics via a machine learning model, fetches and extracts semantic signals from the live HTML, and uses a learned fusion approach to produce an explainable, highly accurate Phishing Risk Score.

## Key Contributions

1. **Hybrid structural + semantic phishing detection.**
2. **Learned fusion of complementary signals.**
3. **Adversarial webpage perturbation/evaluation.**
4. **Hard-negative training for legitimate complex URLs.**
5. **Explainable risk scoring.**
6. **Browser/dashboard deployment.**

## Architecture

The PhishOut engine operates sequentially:
**URL / Webpage** → **Structural Analysis** → **Semantic Analysis** → **Learned Fusion** → **Risk Score** → **Verdict + Explanations**

*Adversarial Research Pipeline:* The repository also contains extensive adversarial evaluation frameworks where legitimate models were tested against semantic and structural perturbations to evaluate boundary robustness.

## Production Model

### V3 Production Model
The current production iteration is **V3**. It includes fixes for script extraction bugs and incorporates additional legitimate hard-negative URLs during training to reduce false positives on complex legitimate pages.
Used by:
- Web Dashboard
- API (`/phishout/scan`)
- Chrome Extension

### V2 Research Baseline
The **V2** model is preserved within the repository as the baseline for our E1–E7 adversarial research experiments. E1–E7 adversarial results remain fully reproducible against V2.

### V4
*Note: Any referenced V4 models/scripts in the archives are experimental/superseded and are not utilized in production.*

## Results

Authoritative validated metrics for the **Production V3** model:
- **F1 Score:** 95.54%
- **Precision:** 95.86%
- **Recall:** 95.23%
- **Test FPR:** 3.27%
- **Hard-negative FPR:** 1.00%

**Legitimate URL Validation:**
Evaluated against an unseen set of 54 highly complex legitimate URLs (e.g., deep Github logins, complex banking URLs, and dev portals):
- **44 SAFE**
- **10 SUSPICIOUS**
- **0 PHISHING**
*(Note: This 54-URL test is a validation set demonstrating structural bias correction, not a universal false-positive guarantee).*

## Features

PhishOut utilizes 51 total features:
- **32 Structural Features:** Evaluates URL depth, domain entropy, special characters, suspicious TLDs, and path lexical features.
- **19 Semantic Features:** Extracts signals from live HTML, including `link_to_form_ratio`, `text_to_script_ratio`, `credential_density`, `brand_context_score`, password fields, form endpoints, and iframe counts.

## Installation

```powershell
# Clone the repository
git clone https://github.com/Dheeraj-Reddy-07/PhishOut.git
cd PhishOut
```

## Running

### 1. Backend
```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```
The API will be available at `http://localhost:8000`.

### 2. Frontend Web Dashboard
```powershell
cd phishguard-react
npm install
npm run dev
```
Open `http://localhost:5173`. If your backend runs elsewhere, set `VITE_API_URL`.

### 3. Chrome Extension (Deployment Prototype)
PhishOut includes an optional Chrome Manifest V3 extension prototype.
- It can scan the current page manually.
- It can automatically detect active authentication/login pages.
- It can display and block detected phishing threats.
- *Note: This is a deployment prototype for testing, not the core research contribution.*

To load it:
1. Start the backend.
2. Open `chrome://extensions/` and enable Developer mode.
3. Select **Load unpacked** and choose the `extension/` directory.

## API

`POST /phishout/scan`

**Example Request:**
```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/phishout/scan -ContentType 'application/json' -Body '{"url":"https://github.com/login"}'
```

**Response includes:**
- `risk_score`: 0-100 combined threat score
- `verdict`: SAFE / SUSPICIOUS / PHISHING
- `structural_score` & `semantic_score`
- `reasons`: Explainable risk indicators

## Research Reproducibility

- **Models:** Production and baseline models are located in `backend/models/`.
- **Scripts:** Training, dataset processing, and evaluation scripts have been organized in `scripts/`.
- **Reports:** The E1–E7 adversarial reports, evaluation metrics, and phase diagnostics are preserved in `docs/research/`.

## Project Structure

```text
PhishOut/
├── backend/           # FastAPI backend and core prediction pipelines
├── docs/              # Research reports, E1-E7 adversarial logs, and results
├── extension/         # Chrome extension deployment prototype
├── phishguard-react/  # React/Vite interactive web dashboard
├── scripts/           # Training and evaluation scripts
├── archive/           # Old experiments and superseded files
├── README.md
└── .gitignore
```

## Limitations

- **Webpage Fetch Failures:** Sites aggressively blocking automated scrapers will result in a timeout, falling back entirely to the structural model analysis.
- **Evaluation Scope:** Some legitimate pages with heavily clustered authentication language and extensive forms (like massive banking portals) can still receive elevated "SUSPICIOUS" risk scores.
- **Finite Mutation Space:** Adversarial perturbation evaluations (E1-E7) were restricted to a finite mutation space; unbounded manual adversarial crafting remains out of scope.

## Future Work

- Broader adversarial mutation space evaluations.
- Hard-label black-box attack implementations.
- Expansion of adversarial training configurations.
- Exploration of multimodal signals (e.g., visual rendering).
- Larger real-world evaluation at scale.

## License

MIT License

## Authors

Dheeraj-Reddy-07
