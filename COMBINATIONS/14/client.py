import socket

def main():
    s = socket.socket()
    s.connect(("localhost", 5131))
    while True:
        menu = s.recv(4096).decode()
        print(menu, end="")
        choice = input()
        s.sendall(choice.encode())
        if choice == "1":
            prompt = s.recv(4096).decode()
            print(prompt, end="")
            name = input()
            s.sendall(name.encode())
            prompt = s.recv(4096).decode()
            print(prompt, end="")
            n = input()
            s.sendall(n.encode())
            for _ in range(int(n)):
                prompt = s.recv(4096).decode()
                print(prompt, end="")
                amt = input()
                s.sendall(amt.encode())
        elif choice == "2":
            resp = s.recv(8192).decode()
            print(resp)
        elif choice == "3":
            break

main()
