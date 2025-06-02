import tkinter as tk
from tkinter import messagebox

def greet():
    username = entry.get()
    messagebox.showinfo("Greeting", f"Hello, {username}!")

# Create main window
root = tk.Tk()
root.title("Cross-Platform Tkinter App")
root.geometry("300x150")  # Same on Windows and Linux

# Widgets
label = tk.Label(root, text="Enter your name:")
label.pack(pady=5)

entry = tk.Entry(root)
entry.pack(pady=5)

button = tk.Button(root, text="Greet", command=greet)
button.pack(pady=10)

# Run app
root.mainloop()
