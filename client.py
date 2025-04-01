import hashlib
import time
import socket
import sys
import threading
import rsa  
import pickle



def handle_receive():
    while True:
        response = client.recv(4096)  # 將接收到的訊息存在response，設定接收訊息上限為4096bytes
        if response:
            print()
            print()
            print(f"[*] 來自節點的訊息: \n{response}\n")



class Trade:
    def __init__(self, sender, receiver, pay, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.pay = pay
        self.fee = fee
        self.message = message



def generate_address():  # 大致與node相同
    public, private = rsa.newkeys(512)
    public_key = public.save_pkcs1()
    private_key = private.save_pkcs1()
    return pub_address_reduce(public_key), priv_address_reduce(private_key)

def pub_address_reduce(pub):  # 大致與node相同
    addr = str(pub).replace('\\n','')
    addr = addr.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
    addr = addr.replace("-----END RSA PUBLIC KEY-----'", '')
    addr = addr.replace(' ', '')
    return addr

def priv_address_reduce(priv):  # 大致與pub的相同
    priv_key = str(priv).replace('\\n','')
    priv_key = priv_key.replace("b'-----BEGIN RSA PRIVATE KEY-----", '')
    priv_key = priv_key.replace("-----END RSA PRIVATE KEY-----'", '')
    priv_key = priv_key.replace(' ', '')
    return priv_key

def trade_to_str(trade): # 把交易資料轉換成字串(以字典形式)
        trade_dict = {
            'sender':str(trade.sender),
            'receiver': str(trade.receiver),
            'pay': trade.pay,
            'fee': trade.fee,
            'message': trade.message
        }
        return str(trade_dict)

def init_trade(sender, receiver, pay, fee, message): # 初始化一筆交易，與node不同的是不需要檢查餘額
    new_trade = Trade(sender, receiver, pay, fee, message)
    return new_trade

def sign_trade(trade, priv):  # 簽名
    priv_key = '-----BEGIN RSA PRIVATE KEY-----\n'
    priv_key += priv
    priv_key += '\n-----END RSA PRIVATE KEY-----\n'
    priv_key_pkcs = rsa.PrivateKey.load_pkcs1(priv_key.encode('utf-8'))  # 存成pkcs1形式
    trade_str = trade_to_str(trade)
    sign = rsa.sign(trade_str.encode('utf-8'), priv_key_pkcs, 'SHA-1')
    return sign



if __name__ == "__main__":
    target_host = "192.168.56.1" # 主機ip位置
    target_port = int(49555)  # 這個程式的socket的接口
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 宣告一個TCP的socket，代表網路連接的端點，名為client
    client.connect((target_host, target_port))  # 連上node

    receive_handler = threading.Thread(target=handle_receive, args=())  # 建立接收訊息的執行緒
    receive_handler.start()

    command_dict = {  # 方便呼叫指令
        "1": "generate_address", 
        "2": "get_balance", 
        "3": "trade", 
        "4": "earn"
    }

    while True:
        print("指令列表:")
        print("1. 生成地址")
        print("2. 查詢餘額")
        print("3. 發起交易")
        print("4. 賺取金額")
        command = input("要使用之指令 : ")
        if str(command) not in command_dict.keys():  # 若輸入了不存在之指令
            print("未知的指令。\n")
            continue
        message = {
            "request": command_dict[str(command)]  # 將想要的操作存在準備傳輸至node的dictionary
        }
        if command_dict[str(command)] == "generate_address":  # 生成地址
            addr, priv_key = generate_address()
            print(f"公鑰地址 : {addr}")
            print(f"私鑰 : {priv_key}\n")

        elif command_dict[str(command)] == "get_balance":  # 查詢餘額
            addr = input("公鑰地址 : ")
            message['address'] = addr
            client.send(pickle.dumps(message))  # 將要求傳送至node
            print()

        elif command_dict[str(command)] == "trade":  # 發起交易
            addr = input("公鑰地址 : ")
            priv_key = input("私鑰 : ")
            receiver = input("接收者 : ")
            pay = input("交易金額 : ")
            fee = input("手續費 : ")
            comment = input("訊息 : ")  # message會撞名
            new_trade = init_trade(  # 創建新交易
                addr, receiver, int(pay), int(fee), comment
            )
            sign = sign_trade(new_trade, priv_key)  # 簽名
            message["data"] = new_trade
            message["sign"] = sign

            client.send(pickle.dumps(message))  # 傳送需求
            print()

        elif command_dict[str(command)] == "earn":  # 賺錢
            addr = input("公鑰地址 : ")
            message['address'] = addr
            client.send(pickle.dumps(message))  # 將要求傳送至node
            print()

        else:  # 若輸出不存在之指令(目前不會觸發)
            print("未知的指令。\n")
        time.sleep(1)  # 等待一下