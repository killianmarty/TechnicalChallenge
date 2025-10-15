import requests
import base64
from flask import Flask, request, jsonify
import logging
import os
from dotenv import load_dotenv

load_dotenv()

LOG_FILE = os.getenv("LOG_FILE", "API.log")
PORT = os.getenv("PORT", 8080)
API_URL = os.getenv("API_URL", "https://www.virustotal.com/api/v3")
API_KEY = os.getenv("API_KEY")

if(not API_KEY):
    raise RuntimeError("No API_KEY specified.")


app = Flask(__name__)

## Logging setup
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)





## Calls VirusTotal API to scan url
def call_api_scan(url):

    id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    response = requests.get(f"{API_URL}/urls/{id}", headers={
        "x-apikey": API_KEY
    })

    return (response.status_code, response.json())
    



## Create a summary of the API call results
def scan_url(url):
    scan_status_code, scan_result = call_api_scan(url)

    if(scan_status_code == 200):
        
        analysis_report = {
            "status": "ok",
            "data": {
                "url": url,
                "malicious_votes": scan_result["data"]["attributes"]["total_votes"]["malicious"],
                "harmless_votes": scan_result["data"]["attributes"]["total_votes"]["harmless"]
            }
        }
        return analysis_report
    
    else:
        return {
            "status": "error"
        }
    




@app.route("/analyze", methods=["POST"])
def scan():

    data = request.get_json()
    ip = request.remote_addr

    ## Handle requests without url parameter
    if not data or "url" not in data:
        logging.error(f"[{ip}] Url not specified.")
        return jsonify({"error": "Url not specified."}), 400
        
    logging.info(f"[{ip}] API call to scan {data["url"]}")
    
    response = scan_url(data["url"])
    logging.info(f"Scanning url {data["url"]}")
    
    ## Handle API call errors
    if(response["status"] == "error"):
        logging.error(f"Error while scanning url {data["url"]}")
        return jsonify({"error": "error while scanning the url."}), 400

    return jsonify(response["data"]), 200
    



if __name__ == "__main__":
    app.run(debug=False, port=PORT)
