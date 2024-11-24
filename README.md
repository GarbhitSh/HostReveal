# HostReveal

**HostReveal** is a comprehensive tool designed to analyze and investigate domains, uncover hosting details, and identify potential cybersecurity risks. It combines advanced techniques such as WHOIS lookup, DNS analysis, traceroute, port scanning, SSL inspection, and AI-powered risk assessment to provide actionable insights.

## Features

- **WHOIS Lookup**: Retrieves domain registration details.
- **DNS Analysis**: Extracts DNS records including A, MX, TXT, and NS records.
- **Traceroute**: Maps the network path to the target domain.
- **Port Scanning**: Identifies open, closed, and filtered ports.
- **SSL Certificate Inspection**: Analyzes the validity and details of SSL certificates.
- **AI Risk Assessment**: Uses machine learning to assess domain safety and detect suspicious activity.
- **Frontend Dashboard**: Interactive React-based dashboard for displaying results.

## Setup Instructions

### Clone the Repository

### Setup Backend
Navigate to the backend folder - cd hostreveal
Install dependencies: pip install django djangorestframework whois dnspython scapy pyopenssl nmap corsheaders
Apply migrations and run the server: 
python manage.py makemigrations
python manage.py migrate
python manage.py runserver


### Setup Frontend
Navigate to the frontend folder: cd hostreveal-frontend
install dependencies: npm install
Start the React frontend:npm start


### Test the Application
Open the frontend at http://localhost:3000.
Enter a domain (e.g., example.com) and click "Investigate".
View the analysis results from the backend.

## Contributing
Contributions are welcome! Please create a pull request with your changes and improvements.

## License
This project is licensed under the MIT License. See the LICENSE file for details.
