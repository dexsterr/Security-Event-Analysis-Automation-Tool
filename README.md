# Security Event Analysis Automation Tool 

A comprehensive security event analysis dashboard with a web interface, built in Python. Detects and analyzes threats, visualizes risk levels over time, and logs all security events in your environment.

---

# Security Event Analysis Automation Tool (EN)

A comprehensive security event analysis dashboard with a web interface, built in Python (Flask).  
Detects and analyzes security events, visualizes threat scores over time, and logs all actions.

---

## How does it work?

1. **Threat Analysis**
   - Fetches threat intelligence data from external sources (e.g., VirusTotal).
   - Uses a basic ML model to classify threats based on available data.
   - Detects and logs potential phishing attempts from email samples.
   - Monitors for brand mentions using external APIs.

2. **Result Logging**
   - Saves each scan result (threat score and timestamp) to a JSON file.
   - Logs all actions and alerts to a text log file.

3. **Dashboard**
   - Displays the latest logs and scan statistics (number of scans, number of detected threats, last threat score).
   - Shows a dynamic chart of threat scores over time.
   - Allows manual triggering of a new scan from the web interface.

4. **Notifications**
   - Sends alerts via email and SMS when a threat or phishing attempt is detected.
   - Optionally sends alerts to SIEM systems.

---

## Requirements

- Python 3.8+
- Flask
- matplotlib
- requests
- scikit-learn
- (optional) docker, twilio, cryptography

---

## Security recommendations

- Use only with data and systems you are authorized to analyze.
- Do not share sensitive API keys or credentials.
- Regularly review logs and backup your results.
- This project is for educational and portfolio purposes.

---

This project demonstrates practical skills in security event automation, data visualization, and alerting.

---

# Narzędzie do Automatycznej Analizy Zdarzeń Bezpieczeństwa (PL)

Prosty i praktyczny dashboard do analizy zdarzeń bezpieczeństwa napisany w Pythonie (Flask).  
Aplikacja automatyzuje analizę zdarzeń, wizualizuje poziom zagrożenia w czasie i loguje wszystkie działania.

---

## Jak to działa?

1. **Analiza zagrożeń**
   - Pobiera dane o zagrożeniach z zewnętrznych źródeł (np. VirusTotal).
   - Wykorzystuje prosty model ML do klasyfikacji zagrożeń na podstawie dostępnych danych.
   - Wykrywa i loguje potencjalne próby phishingu na podstawie próbek e-maili.
   - Monitoruje wzmianki o marce w zewnętrznych serwisach.

2. **Logowanie wyników**
   - Zapisuje każdy wynik skanowania (poziom zagrożenia i datę) do pliku JSON.
   - Loguje wszystkie działania i alerty do pliku tekstowego.

3. **Dashboard**
   - Wyświetla najnowsze logi i statystyki skanów (liczba skanów, liczba wykrytych zagrożeń, ostatni wynik).
   - Pokazuje dynamiczny wykres poziomu zagrożenia w czasie.
   - Pozwala ręcznie uruchomić nowy skan z poziomu przeglądarki.

4. **Powiadomienia**
   - Wysyła alerty e-mail i SMS po wykryciu zagrożenia lub phishingu.
   - Opcjonalnie wysyła alerty do systemów SIEM.

---

## Wymagania

- Python 3.8+
- Flask
- matplotlib
- requests
- scikit-learn
- (opcjonalnie) docker, twilio, cryptography

---

## Zalecenia bezpieczeństwa

- Używaj tylko z danymi i systemami, do których masz uprawnienia.
- Nie udostępniaj kluczy API ani haseł.
- Regularnie przeglądaj logi i wykonuj kopie zapasowe wyników.
- Projekt do celów edukacyjnych i portfolio.

---

Projekt pokazuje praktyczne umiejętności z zakresu automatyzacji analizy bezpieczeństwa, wizualizacji danych i alertowania.
