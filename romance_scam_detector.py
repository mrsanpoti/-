
import sys

# Data Model for Scam Detection
scam_detection_model = {
    "romance_scam_keywords": [
        {"keyword": "love you", "risk_level": "high"},
        {"keyword": "money", "risk_level": "high"},
        {"keyword": "urgent", "risk_level": "medium"},
        {"keyword": "secret", "risk_level": "low"},
        {"keyword": "investment", "risk_level": "high"},
        {"keyword": "dear", "risk_level": "low"},
        {"keyword": "honey", "risk_level": "low"},
        {"keyword": "my heart", "risk_level": "low"},
        {"keyword": "bank account", "risk_level": "high"},
        {"keyword": "transfer", "risk_level": "high"}
    ],
    "suspicious_phrases": [
        {"phrase": "家族の病気で急な出費が必要", "risk_level": "high"},
        {"phrase": "すぐに送金してほしい", "risk_level": "high"},
        {"phrase": "会うのはもう少し待って", "risk_level": "medium"},
        {"phrase": "高額な投資話", "risk_level": "high"},
        {"phrase": "ビジネスパートナー", "risk_level": "medium"},
        {"phrase": "税金を支払う", "risk_level": "high"},
        {"phrase": "相続", "risk_level": "high"}
    ]
}

class MessageProcessor:
    """Handles the initial processing of incoming messages."""
    def process_message(self, message):
        """Cleans and extracts features from the raw message."""
        print(f"[MessageProcessor] Processing message: '{message}'")
        cleaned_message = message.lower()
        extracted_features = {"text": cleaned_message}
        print(f"[MessageProcessor] Cleaned message and extracted features.")
        return extracted_features

class ScamDetector:
    """Analyzes processed messages to identify potential scam patterns."""
    def __init__(self, detection_model):
        """Initializes the detector with a scam detection model."""
        self.detection_model = detection_model
        print("[ScamDetector] Initialized with detection model.")

    def detect_scam(self, processed_message):
        """Applies detection algorithms to identify fraudulent patterns."""
        print(f"[ScamDetector] Detecting scam in processed message: '{processed_message['text']}'")
        risk_score = 0
        warnings = []

        for keyword_data in self.detection_model.get("romance_scam_keywords", []):
            keyword = keyword_data["keyword"]
            risk_level = keyword_data["risk_level"]
            if keyword in processed_message["text"]:
                risk_score += (3 if risk_level == "high" else (2 if risk_level == "medium" else 1))
                warnings.append(f"Keyword '{keyword}' detected (risk: {risk_level})")

        for phrase_data in self.detection_model.get("suspicious_phrases", []):
            phrase = phrase_data["phrase"].lower()
            risk_level = phrase_data["risk_level"]
            if phrase in processed_message["text"]:
                risk_score += (3 if risk_level == "high" else (2 if risk_level == "medium" else 1))
                warnings.append(f"Phrase '{phrase}' detected (risk: {risk_level})")

        detection_result = {"is_scam": risk_score > 0, "risk_score": risk_score, "warnings": warnings}
        print(f"[ScamDetector] Detection complete. Result: {detection_result}")
        return detection_result

class WarningGenerator:
    """Generates appropriate warnings based on the detection results."""
    def generate_warning(self, detection_result):
        """Constructs a comprehensive warning message and recommended actions."""
        print(f"[WarningGenerator] Generating warning for result: {detection_result}")
        warning_message = "No specific scam detected."
        recommended_actions = "Continue with caution."

        if detection_result.get("is_scam"):
            risk_score = detection_result.get("risk_score", 0)
            warnings_found = detection_result.get("warnings", [])

            if risk_score >= 5:
                warning_message = "HIGH RISK OF ROMANCE SCAM!"
                recommended_actions = "STOP all communication immediately. Block the sender. Seek advice from a trusted friend or authority."
            elif risk_score >= 2:
                warning_message = "MODERATE RISK OF ROMANCE SCAM."
                recommended_actions = "Proceed with extreme caution. DO NOT send money or personal information. Verify identity independently."
            else:
                warning_message = "LOW RISK OF SUSPICIOUS ACTIVITY."
                recommended_actions = "Be alert for further suspicious signs. Do not share financial details."

            if warnings_found:
                warning_message += f" Found: {'; '.join(warnings_found)}"

        print(f"[WarningGenerator] Generated warning message and actions.")
        return {"message": warning_message, "actions": recommended_actions}

class OutputHandler:
    """Manages the output and delivery of warnings."""
    def deliver_warning(self, warning_output):
        """Logs or displays the generated warning."""
        print("[OutputHandler] Delivering warning...")
        print("===========================================")
        print("*** SCAM DETECTION ALERT ***")
        print(f"Message: {warning_output['message']}")
        print(f"Recommended Actions: {warning_output['actions']}")
        print("===========================================")
        print("[OutputHandler] Warning delivered.")

# Main execution flow for the CLI application
if __name__ == "__main__":
    # 1. Instantiate components
    processor = MessageProcessor()
    detector = ScamDetector(scam_detection_model)
    generator = WarningGenerator()
    handler = OutputHandler()

    print("\n--- Romance Scam Detector CLI Prototype ---")
    print("Enter a message to analyze, or type 'exit' or 'quit' to end.")

    # 2. Infinite loop for user input
    while True:
        try:
            user_input = input("\nEnter message: ")

            # 3. Check for exit commands
            if user_input.lower() in ["exit", "quit"]:
                print("Exiting Romance Scam Detector. Goodbye!")
                break

            if not user_input.strip():
                print("Please enter a non-empty message.")
                continue

            # 4. Process the message
            processed_data = processor.process_message(user_input)

            # 5. Detect scams
            detection_results = detector.detect_scam(processed_data)

            # 6. Generate warning
            warning_output = generator.generate_warning(detection_results)

            # 7. Deliver warning
            handler.deliver_warning(warning_output)

        except EOFError:
            print("\nEOF encountered. Exiting Romance Scam Detector. Goodbye!")
            break
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            print("Exiting Romance Scam Detector due to an error.")
            break
