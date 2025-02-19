# Import necessary modules
import tkinter as tk
from tkinter import ttk, messagebox
import base64
import re

# Conversion functions
def text_to_hex(text):
    return ' '.join(format(ord(c), 'x') for c in text)

def hex_to_text(hex_str):
    return ''.join(chr(int(h, 16)) for h in hex_str.split())

def text_to_decimal(text):
    return ' '.join(str(ord(c)) for c in text)

def decimal_to_text(decimal_str):
    return ''.join(chr(int(d)) for d in decimal_str.split())

def text_to_binary(text):
    return ' '.join(format(ord(c), 'b').zfill(8) for c in text)

def binary_to_text(binary_str):
    return ''.join(chr(int(b, 2)) for b in binary_str.split())

def text_to_base64(text):
    return base64.b64encode(text.encode()).decode()

def base64_to_text(base64_str):
    return base64.b64decode(base64_str.encode()).decode()

def text_to_morse(text):
    morse_code = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
        '9': '----.', '0': '-----', ' ': '/'
    }
    return ' '.join(morse_code.get(c.upper(), c) for c in text)

def morse_to_text(morse):
    morse_code = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..',
        '9': '----.', '0': '-----', ' ': '/'
    }
    text_code = {v: k for k, v in morse_code.items()}
    return ''.join(text_code.get(m, m) for m in morse.split())

def text_to_braille(text):
    braille_code = {
        'a': '⠁', 'b': '⠃', 'c': '⠉', 'd': '⠙', 'e': '⠑', 'f': '⠋',
        'g': '⠛', 'h': '⠓', 'i': '⠊', 'j': '⠚', 'k': '⠅', 'l': '⠇',
        'm': '⠍', 'n': '⠝', 'o': '⠕', 'p': '⠏', 'q': '⠟', 'r': '⠗',
        's': '⠎', 't': '⠞', 'u': '⠥', 'v': '⠧', 'w': '⠺', 'x': '⠭',
        'y': '⠽', 'z': '⠵', '1': '⠼⠁', '2': '⠼⠃', '3': '⠼⠉',
        '4': '⠼⠙', '5': '⠼⠑', '6': '⠼⠋', '7': '⠼⠛', '8': '⠼⠓',
        '9': '⠼⠊', '0': '⠼⠚'
    }
    return ''.join(braille_code.get(c.lower(), c) for c in text)

def braille_to_text(braille):
    text_code = {
        '⠁': 'a', '⠃': 'b', '⠉': 'c', '⠙': 'd', '⠑': 'e', '⠋': 'f',
        '⠛': 'g', '⠓': 'h', '⠊': 'i', '⠚': 'j', '⠅': 'k', '⠇': 'l',
        '⠍': 'm', '⠝': 'n', '⠕': 'o', '⠏': 'p', '⠟': 'q', '⠗': 'r',
        '⠎': 's', '⠞': 't', '⠥': 'u', '⠧': 'v', '⠺': 'w', '⠭': 'x',
        '⠽': 'y', '⠵': 'z', '⠼⠁': '1', '⠼⠃': '2', '⠼⠉': '3',
        '⠼⠙': '4', '⠼⠑': '5', '⠼⠋': '6', '⠼⠛': '7', '⠼⠓': '8',
        '⠼⠊': '9', '⠼⠚': '0'
    }
    result = []
    i = 0
    while i < len(braille):
        if braille[i] == '⠼':  # Number prefix
            result.append(text_code.get(braille[i:i+2], braille[i:i+2]))
            i += 2
        else:
            result.append(text_code.get(braille[i], braille[i]))
            i += 1
    return ''.join(result)

# Function to detect input type and set conversion type accordingly
def detect_input_type(event=None):
    text = text_input.get("1.0", tk.END).strip()
    
    if all(c in '01 ' for c in text):
        input_type_var.set("Binary")
        conversion_type_var.set("Text")
    elif all(c in '0123456789 ' for c in text):
        input_type_var.set("Decimal")
        conversion_type_var.set("Text")
    elif re.fullmatch(r'[0-9a-fA-F ]+', text):
        input_type_var.set("Hex")
        conversion_type_var.set("Text")
    elif re.fullmatch(r'[A-Za-z0-9+/= ]+', text) and len(text) % 4 == 0:
        input_type_var.set("Base64")
        conversion_type_var.set("Text")
    elif re.fullmatch(r'[\.\- /]+', text):
        input_type_var.set("Morse")
        conversion_type_var.set("Text")
    elif re.fullmatch(r'[⠁-⠟⠼ ]+', text):
        input_type_var.set("Braille")
        conversion_type_var.set("Text")
    else:
        input_type_var.set("Text")
        conversion_type_var.set("Braille")

# Function to convert text
def convert_text():
    input_type = input_type_var.get()
    conversion_type = conversion_type_var.get()
    text = text_input.get("1.0", tk.END).strip()

    try:
        if input_type == "Text" and conversion_type == "Hex":
            output = text_to_hex(text)
        elif input_type == "Hex" and conversion_type == "Text":
            output = hex_to_text(text)
        elif input_type == "Text" and conversion_type == "Decimal":
            output = text_to_decimal(text)
        elif input_type == "Decimal" and conversion_type == "Text":
            output = decimal_to_text(text)
        elif input_type == "Text" and conversion_type == "Binary":
            output = text_to_binary(text)
        elif input_type == "Binary" and conversion_type == "Text":
            output = binary_to_text(text)
        elif input_type == "Text" and conversion_type == "Base64":
            output = text_to_base64(text)
        elif input_type == "Base64" and conversion_type == "Text":
            output = base64_to_text(text)
        elif input_type == "Text" and conversion_type == "Morse":
            output = text_to_morse(text)
        elif input_type == "Morse" and conversion_type == "Text":
            output = morse_to_text(text)
        elif input_type == "Text" and conversion_type == "Braille":
            output = text_to_braille(text)
        elif input_type == "Braille" and conversion_type == "Text":
            output = braille_to_text(text)
        else:
            messagebox.showerror("Error", "Invalid conversion types selected")
            return
    except Exception as e:
        messagebox.showerror("Error", str(e))
        return

    output_text.config(state=tk.NORMAL)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, output)
    output_text.config(state=tk.DISABLED)

# Function to copy text to clipboard
def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(output_text.get("1.0", tk.END).strip())
    messagebox.showinfo("Copied", "Output copied to clipboard")

# Function to clear text fields
def clear_text():
    text_input.delete("1.0", tk.END)
    output_text.config(state=tk.NORMAL)
    output_text.delete("1.0", tk.END)
    output_text.config(state=tk.DISABLED)

# Context menu for right-click
def show_context_menu(event):
    context_menu.post(event.x_root, event.y_root)

def cut_text():
    text_input.event_generate("<<Cut>>")

def copy_text():
    text_input.event_generate("<<Copy>>")

def paste_text():
    text_input.event_generate("<<Paste>>")
    root.after(100, detect_input_type)  # Detect input type after pasting

def select_all():
    text_input.tag_add(tk.SEL, "1.0", tk.END)
    text_input.mark_set(tk.INSERT, "1.0")
    text_input.see(tk.INSERT)

root = tk.Tk()
root.title("Text Converter Tool")
root.geometry("700x550")
root.configure(bg="#10265e")

# Style configurations
style = ttk.Style()
style.configure("TButton", font=("Arial", 12), padding=10)
style.configure("TLabel", background="#10265e", foreground="white", font=("Arial", 12, "bold"))
style.configure("TFrame", background="#10265e")
style.configure("TText", background="#1d3a85", foreground="white", font=("Arial", 12))

# Main Frame
main_frame = ttk.Frame(root, padding="10")
main_frame.pack(expand=True)

# Title
title_label = ttk.Label(main_frame, text="Text Converter Tool", font=("Arial", 18, "bold"), anchor="center")
title_label.grid(row=0, column=0, columnspan=2, pady=10)

# Text input
text_input = tk.Text(main_frame, height=5, width=70, bg="#1d3a85", fg="white", font=("Arial", 12))
text_input.grid(row=1, column=0, columnspan=2, pady=10)

# Bind right-click to show context menu
text_input.bind("<Button-3>", show_context_menu)
text_input.bind("<KeyRelease>", detect_input_type)  # Detect input type on key release
text_input.bind("<<Paste>>", paste_text)  # Bind paste event to custom paste handler

# Input type
input_type_label = ttk.Label(main_frame, text="Input Type:")
input_type_label.grid(row=2, column=0, pady=10, sticky="e")
input_type_var = tk.StringVar(value="Text")
input_type_menu = ttk.Combobox(main_frame, textvariable=input_type_var, values=["Text", "Hex", "Decimal", "Binary", "Base64", "Morse", "Braille"])
input_type_menu.grid(row=2, column=1, pady=10, sticky="w")

# Load PNG images
convert_icon = tk.PhotoImage(file="images/convert_icon.png")  # Replace with your PNG path
copy_icon = tk.PhotoImage(file="images/copy_icon.png")        # Replace with your PNG path
clear_icon = tk.PhotoImage(file="images/clear_icon.png")      # Replace with your PNG path

# Conversion type
conversion_type_label = ttk.Label(main_frame, text="Conversion Type:")
conversion_type_label.grid(row=3, column=0, pady=10, sticky="e")
conversion_type_var = tk.StringVar(value="Braille")
conversion_type_menu = ttk.Combobox(main_frame, textvariable=conversion_type_var, values=["Braille", "Morse", "Binary", "Hex", "Decimal", "Base64", "Text"])
conversion_type_menu.grid(row=3, column=1, pady=10, sticky="w")

# Convert button
convert_button = ttk.Button(main_frame, text="Convert", image=convert_icon, compound="left", command=convert_text)
convert_button.grid(row=4, column=0, columnspan=2, pady=10)

# Output text
output_text = tk.Text(main_frame, height=5, width=70, bg="#1d3a85", fg="white", font=("Arial", 12), state=tk.DISABLED)
output_text.grid(row=5, column=0, columnspan=2, pady=10)

# Copy button
copy_button = ttk.Button(main_frame, text="Copy", image=copy_icon, compound="left", command=copy_to_clipboard)
copy_button.grid(row=6, column=0, pady=15, sticky="e")

# Clear button
clear_button = ttk.Button(main_frame, text="Clear", image=clear_icon, compound="left", command=clear_text)
clear_button.grid(row=6, column=1, pady=15, sticky="w")

# Context menu definition
context_menu = tk.Menu(root, tearoff=0)
context_menu.add_command(label="Cut", command=cut_text)
context_menu.add_command(label="Copy", command=copy_text)
context_menu.add_command(label="Paste", command=paste_text)
context_menu.add_separator()
context_menu.add_command(label="Select All", command=select_all)

root.mainloop()
