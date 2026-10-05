import os
import logging
from flask import Flask, request, jsonify
from config.settings import Config
from engine.orchestrator import process_alert

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)

# Configure logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s - [%(levelname)s] - %(name)s - %(message)s",
    handlers=[
        logging.FileHandler("logs/automation.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger("SOC_Server")

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint for monitor probes.
    """
    return jsonify({
        "status": "healthy",
        "service": "SOC Automation Webhook Server",
        "version": "1.0.0"
    }), 200

@app.route('/api/v1/alert', methods=['POST'])
def receive_alert():
    """
    Webhook endpoint to ingest raw alerts from SIEM (Splunk/Suricata).
    """
    try:
        payload = request.get_json(force=True, silent=True)
        if not payload:
            logger.error("Received request with missing or invalid JSON payload")
            return jsonify({"status": "error", "message": "Invalid JSON body"}), 400

        logger.info(f"Received webhook alert request from IP: {request.remote_addr}")

        # Run pipeline orchestrator
        result = process_alert(payload)

        return jsonify({
            "status": "success",
            "message": "Alert processed successfully",
            "data": result
        }), 200

    except Exception as e:
        logger.error(f"Internal server error processing alert: {e}", exc_info=True)
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    logger.info(f"Starting SOC Automation Platform Webhook Server on port {Config.PORT}...")
    app.run(host='0.0.0.0', port=Config.PORT, debug=True)
