import tkinter as tk
from tkinter import ttk

def create_message_window():
    # Create the main window
    window = tk.Tk()
    window.title("Repetitive Greetings")
    window.geometry("300x650") # Adjusted size to fit content

    # --- Styling (Optional, but makes it look a bit nicer) ---
    style = ttk.Style()
    try:
        # Attempt to use a modern theme if available
        style.theme_use('clam') 
    except tk.TclError:
        print("Clam theme not available, using default.")
        # Fallback to the first available theme if 'clam' is not present
        if style.theme_names():
            try:
                style.theme_use(style.theme_names()[0])
            except tk.TclError:
                print("No ttk themes available.")
        else:
            print("No ttk themes available at all.")

    style.configure("TLabel", padding=5, font=('Helvetica', 10))
    style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'), foreground="#333")
    style.configure("Main.TFrame", background="#f0f0f0") # Light grey background

    # Create a main frame to hold the content
    main_frame = ttk.Frame(window, padding="10", style="Main.TFrame")
    main_frame.pack(expand=True, fill=tk.BOTH)

    # --- Display "hello anas" 10 times ---
    ttk.Label(main_frame, text="Messages for Anas:", style="Header.TLabel").pack(pady=(0, 5))
    for i in range(10):
        ttk.Label(main_frame, text=f"{i+1}. hello anas").pack(anchor='w')

    # Add a separator
    ttk.Separator(main_frame, orient='horizontal').pack(fill='x', pady=10)

    # --- Display "poda yamin" 10 times ---
    ttk.Label(main_frame, text="Messages for Yamin:", style="Header.TLabel").pack(pady=(0, 5))
    for i in range(10):
        ttk.Label(main_frame, text=f"{i+1}. poda yamin").pack(anchor='w')
    
    # --- Close button ---
    close_button = ttk.Button(main_frame, text="Close", command=window.destroy)
    close_button.pack(pady=(20,0))

    # Start the Tkinter event loop
    window.mainloop()

if __name__ == '__main__':
    create_message_window()
