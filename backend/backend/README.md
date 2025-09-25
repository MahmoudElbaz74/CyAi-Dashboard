# Cybersecurity Application

## Overview
This project is a cybersecurity application designed to provide various functionalities including network detection, malware analysis, link analysis, and AI-driven insights. The application is built using FastAPI, allowing for efficient and scalable web services.

## Project Structure
```
backend
├── src
│   ├── main.py                # Entry point of the FastAPI application
│   ├── network_detection       # Module for network detection
│   │   ├── __init__.py
│   │   └── detector.py
│   ├── malware_analysis        # Module for malware analysis
│   │   ├── __init__.py
│   │   └── analyzer.py
│   ├── link_analysis           # Module for link analysis
│   │   ├── __init__.py
│   │   └── analyzer.py
│   ├── ai_agent                # Module for AI agent functionalities
│   │   ├── __init__.py
│   │   └── agent.py
│   └── types                   # Directory for data schemas
│       └── schemas.py
├── requirements.txt            # Project dependencies
└── README.md                   # Project documentation
```

## Setup Instructions
1. Clone the repository:
   ```
   git clone <repository-url>
   cd backend
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Run the FastAPI application:
   ```
   uvicorn src.main:app --reload
   ```

## Usage
- Access the API documentation at `http://localhost:8000/docs` after starting the application.
- The application provides endpoints for:
  - Network detection
  - Malware analysis
  - Link analysis
  - AI agent functionalities

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for any enhancements or bug fixes.

## License
This project is licensed under the MIT License. See the LICENSE file for details.