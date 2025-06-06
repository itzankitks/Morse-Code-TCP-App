import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
import socket
import threading
import time
import json

class MorseCodeApp:
    # Morse code dictionary
    MORSE_CODE_DICT = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
        'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
        'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
        'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
        'Z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
        '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
        '0': '-----', ', ': '--..--', '.': '.-.-.-', '?': '..--..',
        '/': '-..-.', '-': '-....-', '(': '-.--.', ')': '-.--.-',
        ' ': '/'  # Space is represented as a forward slash in Morse code
    }
    
    # Reverse dictionary for decoding
    REVERSE_MORSE_DICT = {v: k for k, v in MORSE_CODE_DICT.items()}
    
    def __init__(self, root):
        self.root = root
        self.root.title("Morse Code TCP Application")
        self.root.geometry("800x600")
        self.root.configure(bg="#f0f0f0")
        
        self.server_socket = None
        self.client_socket = None
        self.is_server = False
        self.connected = False
        
        self.create_widgets()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def create_widgets(self):
        # Create notebook for tabbed interface
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Connection tab
        self.connection_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.connection_frame, text="Connection")
        
        # Morse Code Converter tab
        self.converter_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.converter_frame, text="Morse Code Converter")
        
        # Communication tab
        self.communication_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.communication_frame, text="Communication")
        
        self.setup_connection_tab()
        self.setup_converter_tab()
        self.setup_communication_tab()
    
    def setup_connection_tab(self):
        # Server section
        server_label = ttk.Label(self.connection_frame, text="Server Setup", font=("Arial", 12, "bold"))
        server_label.grid(row=0, column=0, columnspan=2, pady=(20, 10), sticky="w")
        
        ttk.Label(self.connection_frame, text="Host:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.server_host_entry = ttk.Entry(self.connection_frame, width=20)
        self.server_host_entry.insert(0, "localhost")
        self.server_host_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        
        ttk.Label(self.connection_frame, text="Port:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.server_port_entry = ttk.Entry(self.connection_frame, width=10)
        self.server_port_entry.insert(0, "12345")
        self.server_port_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        
        self.start_server_button = ttk.Button(self.connection_frame, text="Start Server", command=self.start_server)
        self.start_server_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)
        
        # Client section
        client_label = ttk.Label(self.connection_frame, text="Client Setup", font=("Arial", 12, "bold"))
        client_label.grid(row=4, column=0, columnspan=2, pady=(20, 10), sticky="w")
        
        ttk.Label(self.connection_frame, text="Server Host:").grid(row=5, column=0, padx=10, pady=5, sticky="w")
        self.client_host_entry = ttk.Entry(self.connection_frame, width=20)
        self.client_host_entry.insert(0, "localhost")
        self.client_host_entry.grid(row=5, column=1, padx=10, pady=5, sticky="w")
        
        ttk.Label(self.connection_frame, text="Server Port:").grid(row=6, column=0, padx=10, pady=5, sticky="w")
        self.client_port_entry = ttk.Entry(self.connection_frame, width=10)
        self.client_port_entry.insert(0, "12345")
        self.client_port_entry.grid(row=6, column=1, padx=10, pady=5, sticky="w")
        
        self.connect_button = ttk.Button(self.connection_frame, text="Connect to Server", command=self.connect_to_server)
        self.connect_button.grid(row=7, column=0, columnspan=2, padx=10, pady=10)
        
        # Status section
        status_label = ttk.Label(self.connection_frame, text="Connection Status", font=("Arial", 12, "bold"))
        status_label.grid(row=0, column=2, columnspan=2, pady=(20, 10), padx=(40, 0), sticky="w")
        
        self.status_text = scrolledtext.ScrolledText(self.connection_frame, width=40, height=15, wrap=tk.WORD)
        self.status_text.grid(row=1, column=2, rowspan=7, padx=(40, 10), pady=5, sticky="nsew")
        self.status_text.config(state=tk.DISABLED)
    
    def setup_converter_tab(self):
        # Text to Morse section
        text_to_morse_label = ttk.Label(self.converter_frame, text="Text to Morse Code", font=("Arial", 12, "bold"))
        text_to_morse_label.grid(row=0, column=0, pady=(20, 10), sticky="w")
        
        self.text_input = scrolledtext.ScrolledText(self.converter_frame, width=40, height=5, wrap=tk.WORD)
        self.text_input.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        
        self.convert_to_morse_button = ttk.Button(self.converter_frame, text="Convert to Morse", command=self.convert_text_to_morse)
        self.convert_to_morse_button.grid(row=2, column=0, padx=10, pady=10)
        
        self.morse_output = scrolledtext.ScrolledText(self.converter_frame, width=40, height=5, wrap=tk.WORD)
        self.morse_output.grid(row=3, column=0, padx=10, pady=5, sticky="nsew")
        
        # Morse to Text section
        morse_to_text_label = ttk.Label(self.converter_frame, text="Morse Code to Text", font=("Arial", 12, "bold"))
        morse_to_text_label.grid(row=0, column=1, pady=(20, 10), padx=(20, 0), sticky="w")
        
        self.morse_input = scrolledtext.ScrolledText(self.converter_frame, width=40, height=5, wrap=tk.WORD)
        self.morse_input.grid(row=1, column=1, padx=(20, 10), pady=5, sticky="nsew")
        
        self.convert_to_text_button = ttk.Button(self.converter_frame, text="Convert to Text", command=self.convert_morse_to_text)
        self.convert_to_text_button.grid(row=2, column=1, padx=(20, 10), pady=10)
        
        self.text_output = scrolledtext.ScrolledText(self.converter_frame, width=40, height=5, wrap=tk.WORD)
        self.text_output.grid(row=3, column=1, padx=(20, 10), pady=5, sticky="nsew")
        
        # Morse code reference
        reference_label = ttk.Label(self.converter_frame, text="Morse Code Reference", font=("Arial", 12, "bold"))
        reference_label.grid(row=4, column=0, columnspan=2, pady=(20, 10), sticky="w")
        
        reference_frame = ttk.Frame(self.converter_frame)
        reference_frame.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        reference_text = "".join([f"{k}: {v}    " for k, v in self.MORSE_CODE_DICT.items()])
        reference = ttk.Label(reference_frame, text=reference_text, wraplength=700)
        reference.pack(fill=tk.BOTH, expand=True)
    
    def setup_communication_tab(self):
        # Message input section
        input_label = ttk.Label(self.communication_frame, text="Message Input", font=("Arial", 12, "bold"))
        input_label.grid(row=0, column=0, pady=(20, 10), sticky="w")
        
        self.message_input = scrolledtext.ScrolledText(self.communication_frame, width=80, height=5, wrap=tk.WORD)
        self.message_input.grid(row=1, column=0, padx=10, pady=5, sticky="nsew")
        
        button_frame = ttk.Frame(self.communication_frame)
        button_frame.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        self.send_as_text_button = ttk.Button(button_frame, text="Send as Text", command=lambda: self.send_message(as_morse=False))
        self.send_as_text_button.grid(row=0, column=0, padx=(0, 10))
        
        self.send_as_morse_button = ttk.Button(button_frame, text="Send as Morse", command=lambda: self.send_message(as_morse=True))
        self.send_as_morse_button.grid(row=0, column=1)
        
        # Message display section
        display_label = ttk.Label(self.communication_frame, text="Communication Log", font=("Arial", 12, "bold"))
        display_label.grid(row=3, column=0, pady=(20, 10), sticky="w")
        
        self.message_display = scrolledtext.ScrolledText(self.communication_frame, width=80, height=15, wrap=tk.WORD)
        self.message_display.grid(row=4, column=0, padx=10, pady=5, sticky="nsew")
        self.message_display.config(state=tk.DISABLED)
    
    def encode_morse(self, text):
        # Convert text to uppercase and encode to Morse code
        text = text.upper()
        morse_code = []
        
        for char in text:
            if char in self.MORSE_CODE_DICT:
                morse_code.append(self.MORSE_CODE_DICT[char])
            elif char == ' ':
                morse_code.append('/')
        
        return ' '.join(morse_code)
    
    def decode_morse(self, morse_code):
        # Decode Morse code to text
        morse_code = morse_code.strip()
        morse_words = morse_code.split(' / ')  # Split into words
        decoded_text = ''
        
        for word in morse_words:
            morse_chars = word.split(' ')
            for char in morse_chars:
                if char in self.REVERSE_MORSE_DICT:
                    decoded_text += self.REVERSE_MORSE_DICT[char]
                elif char == '':
                    continue
                else:
                    decoded_text += '?'  # Unknown Morse sequence
            decoded_text += ' '
        
        return decoded_text.strip()
    
    def convert_text_to_morse(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if text:
            morse_code = self.encode_morse(text)
            self.morse_output.delete("1.0", tk.END)
            self.morse_output.insert(tk.END, morse_code)
    
    def convert_morse_to_text(self):
        morse_code = self.morse_input.get("1.0", tk.END).strip()
        if morse_code:
            text = self.decode_morse(morse_code)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert(tk.END, text)
    
    def update_status(self, message):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.status_text.see(tk.END)
        self.status_text.config(state=tk.DISABLED)
    
    def update_message_display(self, sender, message, is_morse=False):
        self.message_display.config(state=tk.NORMAL)
        
        timestamp = time.strftime('%H:%M:%S')
        if is_morse:
            display_text = f"{timestamp} - {sender} (Morse): {message}\n"
            # Also show decoded text if it's Morse
            decoded = self.decode_morse(message)
            display_text += f"{timestamp} - Decoded: {decoded}\n"
        else:
            display_text = f"{timestamp} - {sender}: {message}\n"
        
        self.message_display.insert(tk.END, display_text)
        self.message_display.see(tk.END)
        self.message_display.config(state=tk.DISABLED)
    
    def start_server(self):
        if self.connected:
            messagebox.showinfo("Info", "Already connected!")
            return
        
        host = self.server_host_entry.get()
        try:
            port = int(self.server_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(1)
            
            self.update_status(f"Server started on {host}:{port}")
            self.start_server_button.config(state=tk.DISABLED)
            
            # Start thread to accept client connection
            threading.Thread(target=self.accept_client, daemon=True).start()
            
            self.is_server = True
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start server: {str(e)}")
    
    def accept_client(self):
        self.update_status("Waiting for client connection...")
        try:
            self.client_socket, addr = self.server_socket.accept()
            self.connected = True
            self.update_status(f"Client connected from {addr[0]}:{addr[1]}")
            
            # Start thread to receive messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            if hasattr(self, 'root') and self.root.winfo_exists():  # Check if root window still exists
                self.update_status(f"Connection error: {str(e)}")
                self.start_server_button.config(state=tk.NORMAL)
    
    def connect_to_server(self):
        if self.connected:
            messagebox.showinfo("Info", "Already connected!")
            return
        
        host = self.client_host_entry.get()
        try:
            port = int(self.client_port_entry.get())
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))
            self.connected = True
            self.is_server = False
            
            self.update_status(f"Connected to server at {host}:{port}")
            self.connect_button.config(state=tk.DISABLED)
            
            # Start thread to receive messages
            threading.Thread(target=self.receive_messages, daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to connect: {str(e)}")
    
    def send_message(self, as_morse=False):
        if not self.connected:
            messagebox.showinfo("Info", "Not connected!")
            return
        
        message = self.message_input.get("1.0", tk.END).strip()
        if not message:
            return
        
        try:
            # Prepare the message with metadata
            if as_morse:
                morse_message = self.encode_morse(message)
                data = {
                    "type": "morse",
                    "content": morse_message
                }
                self.update_message_display("You", morse_message, is_morse=True)
            else:
                data = {
                    "type": "text",
                    "content": message
                }
                self.update_message_display("You", message)
            
            # Send the message as JSON
            self.client_socket.sendall((json.dumps(data) + "\n").encode('utf-8'))
            
            # Clear the input field
            self.message_input.delete("1.0", tk.END)
        except Exception as e:
            self.update_status(f"Failed to send message: {str(e)}")
            self.handle_disconnect()
    
    def receive_messages(self):
        buffer = ""
        
        while self.connected:
            try:
                # Receive data
                data = self.client_socket.recv(4096)
                if not data:
                    # Connection closed
                    self.handle_disconnect()
                    break
                
                # Add received data to buffer
                buffer += data.decode('utf-8')
                
                # Process complete messages
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    try:
                        message = json.loads(line)
                        message_type = message.get("type", "text")
                        content = message.get("content", "")
                        
                        # Update UI based on message type
                        if message_type == "morse":
                            self.update_message_display("Remote", content, is_morse=True)
                        else:
                            self.update_message_display("Remote", content)
                    except json.JSONDecodeError:
                        self.update_status(f"Received invalid message format")
            
            except Exception as e:
                if self.connected:  # Only show error if we haven't already handled disconnect
                    self.update_status(f"Connection error: {str(e)}")
                    self.handle_disconnect()
                break
    
    def handle_disconnect(self):
        self.connected = False
        
        if self.is_server:
            self.start_server_button.config(state=tk.NORMAL)
        else:
            self.connect_button.config(state=tk.NORMAL)
        
        self.update_status("Disconnected")
        
        # Close sockets
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
            
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
    
    def on_closing(self):
        if self.connected:
            self.handle_disconnect()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MorseCodeApp(root)
    root.mainloop()