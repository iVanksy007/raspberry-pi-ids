Raspberry Pi Network Intrusion Detection System

A lightweight machine learning-based IDS built on Raspberry Pi 4B.

Overview
- Detects 7 attack types in real time using Random Forest (99.83% accuracy)
- Live packet capture using Scapy
- Flask web dashboard with threat level indicator, charts and email alerts
- Trained on CICIDS 2017 dataset

Tech Stack
Python, Scikit-learn, Flask, Scapy, Raspberry Pi 4B

Project Structure
- scripts/ — preprocessing, training and evaluation scripts
- app.py — Flask dashboard and live packet classifier (deployed on Pi)
- models/ — trained model files (not included due to file size)

Results
| Model | Accuracy | F1-Score |
|---|---|---|
| Random Forest | 99.83% | 0.998 |
| Decision Tree | 99.70% | 0.997 |

Author
Ivan Dimitrov Stoyanov — BSc (Hons) Computer Science (Cybersecurity)
University of Greenwich, 2026
