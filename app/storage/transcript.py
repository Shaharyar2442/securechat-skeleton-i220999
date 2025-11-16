
import json
import base64
from app.common import utils
from app.crypto import sign

class TranscriptManager:
    def __init__(self, peer_name, our_cert_fingerprint):
        self.peer_name = peer_name
        self.our_fingerprint = our_cert_fingerprint
        self.lines = []
        print(f"TranscriptManager initialized for peer: {peer_name}")

    def add_message(self, seqno, ts, ct_b64, sig_b64, sender_fingerprint):
        """Adds a log line for a sent or received message."""
        line = f"{seqno}|{ts}|{ct_b64}|{sig_b64}|{sender_fingerprint}"
        self.lines.append(line)

    def get_transcript_data(self):
        """Returns the full transcript as a single string."""
        return "\n".join(self.lines)

    def generate_receipt(self, our_private_key, first_seq, last_seq):
        
        transcript_data = self.get_transcript_data()
        transcript_hash = utils.sha256_hex(transcript_data)
        
        signature = sign.sign_data(our_private_key, transcript_hash.encode('utf-8'))
        
        receipt = {
            "type": "receipt",
            "peer": self.peer_name,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": transcript_hash,
            "sig": base64.b64encode(signature).decode('utf-8')
        }
        return receipt

    def save_session(self, receipt_dict, our_cert_file, peer_cert_file):
        """Saves the transcript log and receipt JSON to disk."""
        transcript_data = self.get_transcript_data()
        
        # Define filenames
        transcript_file = f"{self.peer_name}_transcript.log"
        receipt_file = f"{self.peer_name}_session_receipt.json"

        # Save the transcript log
        with open(transcript_file, "w") as f:
            f.write(transcript_data)
        print(f"Transcript saved to {transcript_file}")

        # Save the receipt
        receipt_to_save = {
            "receipt_hash": receipt_dict["transcript_sha256"],
            "signature_b64": receipt_dict["sig"],
            "our_cert_file": our_cert_file,
            "peer_cert_file": peer_cert_file,
            "transcript_file": transcript_file
        }
        with open(receipt_file, "w") as f:
            json.dump(receipt_to_save, f, indent=2)
        print(f"Receipt saved to {receipt_file}")