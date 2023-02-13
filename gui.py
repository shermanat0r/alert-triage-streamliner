 #!/usr/env/python3.10

import tkinter as tk
from tkinter import ttk

class Entity:
    def __init__(self, master, entity_type, parent):
        self.master = master
        self.entity_type = entity_type
        self.parent = parent
        self.frame = ttk.Frame(self.master, relief="solid", borderwidth=1)
        self.label = ttk.Label(self.frame, text=self.entity_type)
        self.entry = ttk.Entry(self.frame)
        self.remove_button = ttk.Button(self.frame, text="Remove", command=self.remove)
        self.label.pack(side="left")
        self.entry.pack(side="left", fill="x", expand=True)
        self.remove_button.pack(side="left")
        self.frame.pack(fill="x", padx=10, pady=10)

    def remove(self):
        self.frame.pack_forget()
        self.parent.entities.remove(self)

class Application(ttk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.master = master
        self.pack(fill="both", expand=True)
        self.create_widgets()

    def create_widgets(self):
        self.alert_name = tk.StringVar()
        self.timestamp = tk.StringVar()

        self.alert_name_label = tk.Label(self.master, text="Alert Name:")
        self.alert_name_label.pack(side="left", padx=10, pady=10)
        self.alert_name_entry = tk.Entry(self.master, textvariable=self.alert_name)
        self.alert_name_entry.pack(side="left", padx=10, pady=10)

        self.timestamp_label = tk.Label(self.master, text="Timestamp:")
        self.timestamp_label.pack(side="left", padx=10, pady=10)
        self.timestamp_entry = tk.Entry(self.master, textvariable=self.timestamp)
        self.timestamp_entry.pack(side="left", padx=10, pady=10)

        self.entity_type = tk.StringVar()
        self.entity_type_label = ttk.Label(self, text="Entity Type:")
        self.entity_type_label.pack(side="left", padx=10, pady=10)
        self.entity_type_dropdown = ttk.OptionMenu(self, self.entity_type, "User", "Hostname", "File hash", "File path", "IP address")
        self.entity_type_dropdown.pack(side="left", padx=10, pady=10)
        self.add_entity_button = ttk.Button(self, text="Add Entity", command=self.add_entity)
        self.add_entity_button.pack(side="left", padx=10, pady=10)
        self.submit_button = ttk.Button(self, text="Submit", command=self.submit)
        self.submit_button.pack(side="right", padx=10, pady=10)
        self.clear_button = ttk.Button(self, text="Clear", command=self.clear)
        self.clear_button.pack(side="right", padx=10, pady=10)
        self.entities = []

    def add_entity(self):
        entity = Entity(self, self.entity_type.get(), self)
        self.entities.append(entity)

    def submit(self):
        for entity in self.entities:
            print(entity.entity_type + ": " + entity.entry.get())
    
    def clear(self):
        for entity in self.entities:
            entity.remove()

root = tk.Tk()
app = Application(master=root)
app.mainloop()

