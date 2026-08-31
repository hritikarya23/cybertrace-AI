# SIH26106 — Phase 14: Forensic Reports

Phase 14 implements HTML and PDF forensic report generation for an owned investigation.

## Endpoints

- `GET /api/v1/investigations/{id}/report/html`
- `GET /api/v1/investigations/{id}/report/pdf`

Admin and analyst roles can export reports. Report files are stored under `REPORT_STORAGE_PATH` and a `reports` database record is created for each generated artifact.

## Included report sections

- Investigation ID and generation time
- Analyst
- Email metadata
- Threat classification
- Risk score and confidence
- SPF/DKIM/DMARC
- Header/routing findings
- Earliest reliable sending node
- IP intelligence / estimated geolocation
- Suspicious URLs
- Domain findings
- AI/NLP/risk indicators
- Graph node/edge summary
- Final assessment
- Attribution limitation note

The report deliberately distinguishes observed evidence from inferred intelligence and never labels IP geolocation as an exact attacker identity/location.

## Run

```bash
pip install -r requirements-phase14.txt
uvicorn app.main:app --reload
```

Then use Swagger at `/docs`.
