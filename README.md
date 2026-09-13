# cloud-misconfig-detector

Lightweight DevSecOps tool that scans **Terraform** IaC for critical **AWS** misconfigurations, tracks risk findings, and exposes results through a **FastAPI** backend and **Streamlit** dashboard.

## Why it exists
Cloud breaches often start as boring misconfigs. This project turns static Terraform review into a repeatable scan → API → dashboard workflow a security engineer can demo.

## What it does
- Parses Terraform configuration
- Checks for high-impact AWS misconfiguration patterns
- Tracks findings / risk context
- Serves results via FastAPI
- Visualizes findings in Streamlit

## Stack
Python · FastAPI · Streamlit · Terraform (IaC input) · AWS security checks

## Run
```bash
# see repository files for exact entrypoints
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# start API / dashboard per project scripts
```

## Security relevance
Useful for **cloud security**, **DevSecOps**, and **shift-left** reviews before infrastructure reaches production.

## Author
Israel Mbiyavanga David — https://israel-david.vercel.app/
