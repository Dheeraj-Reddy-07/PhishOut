# PhishOut

Research-focused phishing webpage detection using hybrid structural URL analysis and semantic HTML analysis. The system produces one fused risk score and includes a FastAPI service, React dashboard, static dashboard, and Chrome Manifest V3 extension.

## Highlights

- 32 structural features and 12 semantic features combined through learned fusion
- Risk score from 0 to 100 with calibrated SAFE, SUSPICIOUS, and PHISHING thresholds
- URL-only fallback when webpage retrieval is unavailable
- Feature-robustness evaluation using plus or minus 5 percent perturbations
- Browser extension warnings and scan history in the dashboards

## Repository Layout

```text
backend/           FastAPI service, feature extraction, models, and research scripts
dashboard/         Static HTML/CSS/JavaScript dashboard
extension/         Chrome Manifest V3 extension
phishguard-react/  React and Vite dashboard
docs/              Research reports and paper-ready result tables
```

## Requirements

- Python 3.10 or newer
- Node.js 18 or newer
- Google Chrome for the extension

## Run the Backend

```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

The API is available at `http://localhost:8000`.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Backend and predictor status |
| `POST` | `/phishout/scan` | Primary structural and semantic PhishOut scan |
| `POST` | `/scan` | Legacy structural-only scan |
| `POST` | `/scan_extended` | Legacy scan with webpage analysis |

Example request:

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/phishout/scan -ContentType 'application/json' -Body '{"url":"https://example.com"}'
```

## Run the React Dashboard

```powershell
cd phishguard-react
npm install
npm run dev
```

Open the Vite URL shown in the terminal, normally `http://localhost:5173`. Set `VITE_API_URL` when the backend is hosted somewhere other than `http://localhost:8000`.

The legacy static dashboard can be opened from `dashboard/index.html` while the backend is running.

## Load the Chrome Extension

1. Start the backend on port 8000.
2. Open `chrome://extensions/` in Chrome and enable Developer mode.
3. Select **Load unpacked** and choose the repository's `extension` directory.
4. Visit an HTTP or HTTPS page and use the PhishGuard popup to scan it.

## Research Results

The selected learned-fusion model was evaluated on the Phish360 test set:

| Model | Accuracy | F1 | ROC-AUC |
| --- | ---: | ---: | ---: |
| Structural-only | 89.37% | 86.50% | 0.9580 |
| Semantic-only | 92.89% | 91.00% | 0.9791 |
| Hybrid | 95.43% | 94.24% | 0.9908 |
| Learned-Fusion PhishOut | 95.43% | 94.26% | 0.9884 |

Calibrated thresholds are SAFE below 15, SUSPICIOUS from 15 through 56, and PHISHING at 57 or above. The worst feature-level F1 degradation was approximately 0.74%. E5, E6, and E7 robustness results are documented in [docs/FINAL_RESULTS.md](docs/FINAL_RESULTS.md).

The Phish360 dataset is not included in this repository. Follow [docs/phish360_dataset.md](docs/phish360_dataset.md) for dataset details and use the local processing scripts where appropriate.

## Validation

```powershell
cd phishguard-react
npm run lint
npm run build
```

Backend smoke tests are in `backend/test_phishout.py`. Start the API first, then run the script from the backend directory:

```powershell
cd backend
python test_phishout.py
```

## Documentation

- [Project plan](docs/PROJECT_PLAN.md)
- [Final research results](docs/FINAL_RESULTS.md)
- [PhishOut architecture](docs/phishout_architecture.md)
- [Task tracker](docs/TASKS.md)

## License

MIT
