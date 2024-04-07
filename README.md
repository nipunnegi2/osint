# DomainAnalyzer

## Overview
DomainAnalyzer is a Python script that provides comprehensive information about a given domain name. It retrieves data such as WHOIS information, DNS records, location details, and VirusTotal analysis results. This tool can be useful for cybersecurity professionals, network administrators, and anyone interested in investigating domain-related information.

## Features
- Retrieves WHOIS information for the domain.
- Resolves DNS records associated with the domain.
- Retrieves location information using IP address geolocation.
- Fetches VirusTotal analysis results for the domain.
- Organizes and presents information in a structured format.

## Dependencies
- Python 3.x
- Required Python libraries: `whois`, `socket`, `dns.resolver`, `requests`

## Usage
1. Clone the repository to your local machine.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Run the script by executing `python domain_analyzer.py`.
4. Enter the domain name when prompted.

## Configuration
Before running the script, make sure to:
- Replace `API_KEY` and `IPINFO_API_KEY` variables in the script with your own API keys for VirusTotal and IPInfo, respectively.

## Disclaimer
This tool is provided for educational and informational purposes only. Usage of this tool for any malicious activities is strictly prohibited. The developers assume no liability and are not responsible for any misuse or damage caused by this script.

## Contribution
Contributions are welcome! If you have any suggestions, bug fixes, or enhancements, feel free to open an issue or submit a pull request.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
