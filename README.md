# AI-Powered Threat Intelligence Agent

A Python-based autonomous threat intelligence system that analyzes suspicious IP addresses using multiple threat intelligence APIs, ML-based classification, and LLM-generated reports.

## What it does
- Accepts a suspicious IP address via REST API
- Queries **VirusTotal** and **AbuseIPDB** for real-time threat intelligence
- Classifies threat severity (**HIGH / MEDIUM / LOW**) using a trained ML model
- Generates a professional threat assessment report using **Gemini AI**
- Logs all results to a **SQLite** database for audit trail

## Tech Stack
Python, Flask, Scikit-learn, Gemini API, VirusTotal API, AbuseIPDB API, SQLite, REST API, Feature Engineering

## Project Structure
