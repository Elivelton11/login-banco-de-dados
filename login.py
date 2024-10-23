from tkinter import messagebox
import sqlite3
import customtkinter as ctk
import bcrypt

#Configuração básica da interface gráfica
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class LoginApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Sistema de Login")
        self.geometry('400x300')

        self.label_username = ctk.CTkLabel(self, text="Usuário")
        self.label_username.pack(pady=10)

        self.entry_username = ctk.CTkEntry(self)
        self.entry_username.pack(pady=5)

        self.label_password = ctk.CTkLabel(self, text="Senha")
        self.label_password.pack(pady=10)

        self.entry_password = ctk.CTkEntry(self, show="*")
        self.entry_password.pack(pady=5)

        self.button_login = ctk.CTkButton(self,text="Login", command=self.login)
        self.button_login.pack(pady=20)

        self.button_register = ctk.CTkButton(self, text="Registrar", command=self.register)
        self.button_register.pack(pady=10)

        self.database_setup()


    def database_setup(self):
        #criação do banco de dados e da tabela de usuários
        self.conn = sqlite3.connect("user.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
        self.conn.commit()

    def register(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        if username and password:
            #Criptografando a senha antes de armazenar
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            try:
                self.cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                self.conn.commit()
                messagebox.showinfo("Sucesso", "Usuário registrado com sucesso!")
            except sqlite3.IntegrityError:
                messagebox.showerror("Erro", "Nome de usuário já existe!")
        else: 
            messagebox.showerror("Erro", "Por favor, preencha todos os campos!")

    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        self.cursor.execute("SELECT password FROM users WHERE username=?", (username,))
        result = self.cursor.fetchone()

        if result:
            stored_password = result[0]   

        #verificando a senha criptografada
            if bcrypt.checkpw(password.encode('utf-8'), stored_password):
                messagebox.showinfo("Sucesso", "Login bem-sucedido!")  
            else: 
                messagebox.showerror("Erro", "Senha incorreta!")
        else: 
            messagebox.showerror("Erro", "Nome de usuário ou senha incorretos!")

if __name__ == "__main__":
    app = LoginApp()
    app.mainloop()       