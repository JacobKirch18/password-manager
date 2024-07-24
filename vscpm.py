# Password Manager
# Jacob Kirchner

import sqlite3
import hashlib
import pyperclip
from tkinter import *
from tkinter import simpledialog
from tkinter import ttk
from functools import partial

# DB
with sqlite3.connect("pm.db") as db:
    cursor = db.cursor()
    
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")


# prompt
def prompt(text):

    if (text == "Website"):
        input_prompt = text
    elif (text == "Username"):
        input_prompt = text
    elif (text == "Password"):
        input_prompt = text
    else:
        pass

    answer = simpledialog.askstring(input_prompt, text, parent=window)
    return answer

# GUI
window = Tk()
window.title("Password Vault")

def hash_password(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


def first_screen():

    window.geometry("350x150")

    lbl = Label(window, text="Create Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl2 = Label(window, text="Re-enter Password")
    lbl2.pack()

    txt2 = Entry(window, width=20, show="*")
    txt2.pack()

    lbl3 = Label(window)
    lbl3.pack()

    def save_password():

        if txt.get() == txt2.get():
            password_hash = hash_password(txt.get().encode('utf-8'))

            insert_password ="""INSERT INTO masterpassword(password)
            VALUES(?)"""
            cursor.execute(insert_password, [(password_hash)])
            db.commit()

            password_vault()

        else:
            lbl3.config(text="Passwords do not match")

    btn = Button(window, text="Submit", command=save_password)
    btn.pack(pady=10)

def login_screen():

    window.geometry("350x150")

    lbl = Label(window, text="Enter Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl2 = Label(window)
    lbl2.pack()

    def get_master():
        check_hash = hash_password(txt.get().encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND password = ?", [(check_hash)])
        return cursor.fetchall()

    def check_password():

        password = get_master()

        if password:
            print("Roll Phi")
            password_vault()
        else:
            txt.delete(0, 'end')
            lbl2.config(text="Wrong password")

    btn = Button(window, text="Submit", command=check_password)
    btn.pack(pady=10)

def password_vault():

    for widget in window.winfo_children():
        widget.destroy()
    
    # frame creation for scrollability
    main_frame = Frame(window)

    main_frame.pack(fill=BOTH,expand=1)

    sec = Frame(main_frame)

    sec.pack(fill=X,side=BOTTOM)

    my_canvas = Canvas(main_frame)

    my_canvas.pack(side=LEFT,fill=BOTH,expand=1)

    y_scrollbar = ttk.Scrollbar(main_frame,orient=VERTICAL,command=my_canvas.yview)
    y_scrollbar.pack(side=RIGHT,fill=Y)

    my_canvas.configure(yscrollcommand=y_scrollbar.set)

    my_canvas.bind("<Configure>",lambda e: my_canvas.config(scrollregion= my_canvas.bbox(ALL))) 

    second_frame = Frame(my_canvas)

    my_canvas.create_window((0,0),window= second_frame, anchor="nw")

    # scroll from anywhere in the window
    def on_mouse_wheel(event):
        my_canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    my_canvas.bind_all("<MouseWheel>", on_mouse_wheel)

    def add():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"

        website = prompt(text1)
        username = prompt(text2)
        password = prompt(text3)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        password_vault()

    def copy(input):
        cursor.execute("SELECT password FROM vault WHERE id = ?", (input,))
        array=cursor.fetchone()
        pword = array[0]
        pyperclip.copy(pword)

    def delete(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        password_vault()

    window.geometry("800x350")

    lbl = Label(second_frame, text="Password Vault")
    lbl.grid(column=1)

    btn = Button(second_frame, text="Add password", command=add)
    btn.grid(column=1, pady=10)

    lbl = Label(second_frame, text="Website")
    lbl.grid(row=2, column=0, padx=88)
    lbl = Label(second_frame, text="Username")
    lbl.grid(row=2, column=1, padx=88)
    lbl = Label(second_frame, text="Password")
    lbl.grid(row=2, column=2, padx=88)

    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True:

            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            txt = Text(second_frame, height=1, borderwidth=0, width=25)
            txt.insert(1.0, array[i][1])
            txt.grid(column=0, row=i+3)

            txt = Text(second_frame, height=1, borderwidth=0, width=25)
            txt.insert(1.0, array[i][2])
            txt.grid(column=1, row=i+3)

            txt = Text(second_frame, height=1, borderwidth=0, width=25)
            txt.insert(1.0, array[i][3])
            txt.grid(column=2, row=i+3)

            cpy_btn = Button(second_frame, text="Copy", command=partial(copy, array[i][0]))
            cpy_btn.grid(column=4, row=i+3, pady=10)

            btn = Button(second_frame, text="Delete", command=partial(delete, array[i][0]))
            btn.grid(column=5, row=i+3, pady=10)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall()) <= i):
                break


check = cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    first_screen()

window.mainloop()

