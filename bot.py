import os
import re
import json
import tempfile
import asyncio
import aiohttp
import shutil
import logging
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec

from telegram import Update, constants
from telegram.ext import (
    ApplicationBuilder,
    ContextTypes,
    MessageHandler,
    CommandHandler,
    filters,
)

# Set up logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)


def load_config():
    if not os.path.exists('config.json'):
        with open('config.json.example', 'r') as sample_config_file:
            sample_config = json.load(sample_config_file)
            with open('config.json', 'w') as config_file:
                json.dump(sample_config, config_file, indent=4)
        raise Exception('Config file not found, we have copied the sample config file for you, please fill in the required information and restart the bot.')
    with open('config.json', 'r') as config_file:
        return json.load(config_file)


TOKEN = load_config().get('bot_token', '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11')


async def load_from_url():
    url = "https://android.googleapis.com/attestation/status"

    timestamp = int(datetime.now().timestamp())
    headers = {
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }

    params = {
        "ts": timestamp
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as response:
            if response.status != 200:
                raise Exception(f"Error fetching data: {response.status}")
            return await response.json()

def parse_number_of_certificates(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    number_of_certificates = root.find('.//NumberOfCertificates')

    if number_of_certificates is not None:
        count = int(number_of_certificates.text.strip())
        return count
    else:
        raise Exception('No NumberOfCertificates found.')

def parse_certificates(xml_file, pem_number):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    pem_certificates = root.findall('.//Certificate[@format="pem"]')

    if pem_certificates is not None:
        pem_contents = [cert.text.strip() for cert in pem_certificates[:pem_number]]
        return pem_contents
    else:
        raise Exception("No Certificate found.")

def load_public_key_from_file(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key

def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def get_overall_status(status, keychain_status, cert_status, google_status):
    if status is None:
        if keychain_status == "Valid":
            if cert_status == "Unknown / Software":
                if google_status == "null":
                    return "Valid (Software signed)"
                else:
                    return f"Something happened {status['reason']}"
            elif cert_status in ("AOSP Software Attestation(EC)", "AOSP Software Attestation(RCA)", "Samsung Knox Attestation", "Google Hardware Attestation"):
                cert_status_map = {
                    "AOSP Software Attestation(EC)": "Valid (AOSP Software EC)",
                    "AOSP Software Attestation(RCA)": "Valid (AOSP Software RCA)",
                    "Samsung Knox Attestation": "Valid (Knox Attestation)",
                    "Google Hardware Attestation": "Valid (Google Hardware Attestation)"
                }
                return cert_status_map.get(cert_status, "Invalid keybox.")
            else:
                return "Invalid keybox."
        else:
            return "Invalid Keybox."
    else:
        status_reason = google_status
        status_reason_map = {
            "KEY_COMPROMISE": "Invalid (Key Compromised)",
            "SOFTWARE_FLAW": "Invalid (Software flaw)",
            "CA_COMPROMISE": "Invalid (CA Compromised)",
            "SUPERSEDED": "Invalid (Suspended)"
        }
        return status_reason_map.get(status_reason, "Valid")

async def keybox_check_cli(keybox_path):
    result_text = ""

    try:
        pem_number = parse_number_of_certificates(keybox_path)
        pem_certificates = parse_certificates(keybox_path, pem_number)
    except Exception as e:
        result_text += f"Error: {e}\n"
        return result_text

    try:
        certificate = x509.load_pem_x509_certificate(
            pem_certificates[0].encode(),
            default_backend()
        )
    except Exception as e:
        result_text += f"Error: {e}\n"
        return result_text

    # Certificate Validity Verification
    serial_number = certificate.serial_number
    serial_number_string = hex(serial_number)[2:].lower()
    not_valid_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    not_valid_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    current_date = datetime.now(timezone.utc)
    validity = not_valid_before <= current_date <= not_valid_after

    # Format validity status
    not_valid_before_str = not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
    not_valid_after_str = not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
    if validity:
        validity_status = f"Valid (Valid from {not_valid_before_str} to {not_valid_after_str})"
    else:
        validity_status = f"Expired (Valid from {not_valid_before_str} to {not_valid_after_str})"

    # Keychain Authentication
    flag = True
    for i in range(pem_number - 1):
        son_certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        father_certificate = x509.load_pem_x509_certificate(pem_certificates[i + 1].encode(), default_backend())

        if son_certificate.issuer != father_certificate.subject:
            flag = False
            break
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()
        try:
            if signature_algorithm in ['sha256WithRSAEncryption', 'sha1WithRSAEncryption', 'sha384WithRSAEncryption',
                                       'sha512WithRSAEncryption']:
                hash_algorithm = {
                    'sha256WithRSAEncryption': hashes.SHA256(),
                    'sha1WithRSAEncryption': hashes.SHA1(),
                    'sha384WithRSAEncryption': hashes.SHA384(),
                    'sha512WithRSAEncryption': hashes.SHA512()
                }[signature_algorithm]
                padding_algorithm = padding.PKCS1v15()
                public_key.verify(signature, tbs_certificate, padding_algorithm, hash_algorithm)
            elif signature_algorithm in ['ecdsa-with-SHA256', 'ecdsa-with-SHA1', 'ecdsa-with-SHA384',
                                         'ecdsa-with-SHA512']:
                hash_algorithm = {
                    'ecdsa-with-SHA256': hashes.SHA256(),
                    'ecdsa-with-SHA1': hashes.SHA1(),
                    'ecdsa-with-SHA384': hashes.SHA384(),
                    'ecdsa-with-SHA512': hashes.SHA512()
                }[signature_algorithm]
                padding_algorithm = ec.ECDSA(hash_algorithm)
                public_key.verify(signature, tbs_certificate, padding_algorithm)
            else:
                raise ValueError("Unsupported signature algorithms")
        except Exception:
            flag = False
            break
    if flag:
        keychain_status = "Valid"
    else:
        keychain_status = "Invalid"

    # Root Certificate Validation
    script_dir = os.path.dirname(os.path.abspath(__file__))
    google_pem = os.path.join(script_dir, 'lib', 'pem', 'google.pem')
    aosp_ec_pem = os.path.join(script_dir, 'lib', 'pem', 'aosp_ec.pem')
    aosp_rsa_pem = os.path.join(script_dir, 'lib', 'pem', 'aosp_rsa.pem')
    knox_pem = os.path.join(script_dir, 'lib', 'pem', 'knox.pem')

    root_certificate = x509.load_pem_x509_certificate(pem_certificates[-1].encode(), default_backend())
    root_public_key = root_certificate.public_key()
    google_public_key = load_public_key_from_file(google_pem)
    aosp_ec_public_key = load_public_key_from_file(aosp_ec_pem)
    aosp_rsa_public_key = load_public_key_from_file(aosp_rsa_pem)
    knox_public_key = load_public_key_from_file(knox_pem)

    if compare_keys(root_public_key, google_public_key):
        cert_status = "Google Hardware Attestation"
    elif compare_keys(root_public_key, aosp_ec_public_key):
        cert_status = "AOSP Software Attestation(EC)"
    elif compare_keys(root_public_key, aosp_rsa_public_key):
        cert_status = "AOSP Software Attestation(RCA)"
    elif compare_keys(root_public_key, knox_public_key):
        cert_status = "Samsung Knox Attestation"
    else:
        cert_status = "Unknown / Software"

    # Validation of certificate revocation
    try:
        status_json = await load_from_url()
    except Exception:
        result_text += "Failed to fetch Google's revoked keybox list.\n"
        status_json = {'entries': {}}

    status = status_json.get('entries', {}).get(serial_number_string, None)
    if status is None:
        google_status = "null"
    else:
        google_status = status['reason']

    overall_status = get_overall_status(status, keychain_status, cert_status, google_status)

    keybox_parsed = f"{certificate.subject}"
    keybox_string = re.search(r"2\.5\.4\.5=([0-9a-fA-F]+)", keybox_parsed)
    if keybox_string:
        keybox_sn = keybox_string.group(1)
        result_text += f"Keybox SN: {keybox_sn}\n"
    else:
        result_text += "Keybox SN: Software or Invalid\n"
    result_text += f"Cert SN: {serial_number_string}\n"
    result_text += f"Status: {overall_status}\n"
    result_text += f"Keychain: {keychain_status}\n"
    result_text += f"Validity: {validity_status}\n"
    result_text += f"Root Cert: {cert_status}\n"
    result_text += f"Check Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"

    return result_text

async def handle_xml_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Get the file
    file = update.message.document

    # Download the file to a temporary location
    file_id = file.file_id
    new_file = await context.bot.get_file(file_id)

    temp_dir = tempfile.mkdtemp()
    secure_random_file_name = os.urandom(16).hex()
    file_path = os.path.join(temp_dir, secure_random_file_name + ".xml")
    await new_file.download_to_drive(custom_path=file_path)

    try:
        # Process the keybox file
        result = await keybox_check_cli(file_path)
    except Exception as e:
        result = f"Error: {e}"

    # Send the result back to the user
    await update.message.reply_text(result)

    # Clean up the temporary directory
    shutil.rmtree(temp_dir)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Hello! Send me a keybox file (.xml), and I'll check it for you.")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Send me a keybox file (.xml), and I'll check it for you.")

def main():
    application = ApplicationBuilder().token(TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.Document.FileExtension("xml"), handle_xml_file))

    application.run_polling()


if __name__ == '__main__':
    if TOKEN == '123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11':
        raise Exception('Please set your bot token in the config file.')
    main()
