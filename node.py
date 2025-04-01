import hashlib
import time
import socket
import sys
import threading
import rsa  # 電腦需要安裝rsa (終端機pip install rsa)
import pickle

class Trade:  # 交易資料的type
    def __init__(self, sender, receiver, pay, fee, message):
        self.sender = sender
        self.receiver = receiver
        self.pay = pay
        self.fee = fee  # 手續費
        self.message = message

class Block:
    def __init__(self, pre_hash, diff, miner, reward):
        self.pre_hash = pre_hash
        self.hash = ""
        self.diff = diff
        self.nonce = 0  # 礦工獲得的前一個區塊的key
        self.timestamp = int(time.time())  # 時間戳記
        self.trades = []  # 儲存的交易資料
        self.miner = miner
        self.reward = reward  # 挖區塊的獎勵

class BlockChain:
    def __init__(self):
        self.adjust_diff = 5  # 幾次挖掘調整一次難度
        self.diff = 4  # 初始難度
        self.min_time = 5  # 低於min_time需增加難度
        self.max_time = 15 # 高於max_time需降低難度
        self.reward = 10  # 挖出一個區塊所得的獎勵
        self.block_limit = 32 # 一個區塊的交易資料數量上限，若太多可能造成挖掘新的nonce耗時過久
        self.chain = []  # 鏈上的區塊
        self.waiting = []  # 等待中的交易(等待被加進區塊裡)

        self.socket_host = "192.168.56.1"  # 主機ip位置(在cmd用ipconfig找)
        self.socket_port = int(49555)  # 這個程式的socket的接口
        self.start_socket_server()  # 開始連接socket

    def trade_to_str(self, trade): # 把交易資料轉換成字串(以字典形式)
        trade_dict = {
            'sender':str(trade.sender),
            'receiver': str(trade.receiver),
            'pay': trade.pay,
            'fee': trade.fee,
            'message': trade.message
        }
        return str(trade_dict)

    def get_trade_str(self, block):  # 獲得區塊上所有交易資料的字串
        trade_str=''
        for trade in block.trades:
            trade_str += self.trade_to_str(trade)
        return trade_str

    def get_hash(self, block, nonce):  # 計算hash值
        s = hashlib.sha1()  # 利用sha1函式計算hash值
        s.update(  # 將以下資料放進sha1裡
            (
                block.pre_hash
                + str(block.timestamp)
                + self.get_trade_str(block)
                + str(nonce)  # 依靠nonce++ ，以及其他資料混和達成隨機取值的效果
            ).encode("utf-8")
        )
        h = s.hexdigest()  # 返回s的摘要
        return h

    def create_genesis_block(self):
        print()
        print("建立創世塊")
        new_block = Block('海の向こうは敵対', self.diff, 'Pomelo0411', self.reward)  # 首個區塊沒有前一個區塊的hash值，可以自己亂打
        new_block.hash = self.get_hash(new_block, 0)  # 算hash
        self.chain.append(new_block)  # 加進鏈裡

    def add_trade_to_block(self, block):  # 將交易資料放入區塊
        self.waiting.sort(key=lambda x: x.fee, reverse=True)  # 將等待中的交易按照手續費由大到小排序好
        if len(self.waiting) > self.block_limit:  # 放入的交易資料數量不能超過limit，以免造成資料量過多
            trade_accept = self.waiting[:self.block_limit]
            self.waiting = self.waiting[self.block_limit:]
        else:
            trade_accept = self.waiting
            self.waiting = []
        block.trades = trade_accept

    def adjust_difficulty(self):
        if len(self.chain)%self.adjust_diff!=1:
            return self.diff
        elif len(self.chain)<=self.adjust_diff: # 一開始不用改
            return self.diff
        else:
            first = self.chain[-1*self.adjust_diff-1].timestamp  # 該次調整內第一次挖掘之時間戳記
            last = self.chain[-1].timestamp  # 該次調整內最後一次挖掘之時間戳記
            avg_time = round((last-first) / (self.adjust_diff), 3)  # 計算平均耗時，使用時間戳記，所以與每次挖掘輸出的耗時有所不同
            if avg_time > self.max_time:  
                print("平均挖掘一個區塊耗時 :", avg_time, "秒，降低難度。") # 平均時間超出設定上限時間 => 降低難度
                self.diff -= 1
            elif avg_time < self.min_time:
                print("平均挖掘一個區塊耗時 :", avg_time, "秒，提高難度。") # 平均時間低於設定下限時間 => 提升難度
                self.diff += 1
            else :
                print("平均挖掘一個區塊耗時 :", avg_time, "秒，不改變難度。")  # 平均耗時介於min_time與max_time之間 => 難度不變

    def mine_block(self, miner): # 挖掘新區塊
        start = time.process_time() # 計時

        last_block = self.chain[-1]
        self.adjust_difficulty()  # 檢查是否需要調整難度
        new_block = Block(last_block.hash, self.diff, miner, self.reward) # 取得上一區塊hash，並建立新區塊

        self.add_trade_to_block(new_block)  # 將交易加進區塊裡
        new_block.pre_hash = last_block.hash
        new_block.hash = self.get_hash(new_block, new_block.nonce)  # 開始嘗試生成hash值

        while new_block.hash[0: self.diff] != '0' * self.diff:  # 判斷0的數量是否達成
            new_block.nonce += 1  # 因為透過hash值轉換，其值可以視為隨機值，且hash值由nonce與其他資料混和而成，可以+1+1慢慢找直到找到符合該難度的hash值。
            new_block.hash = self.get_hash(new_block, new_block.nonce)  # 找出該nonce是否可以作為此區塊hash值

        time_consumed = round(time.process_time() - start, 5)  # 計算從開始計時到現在過了多久，作為耗時
        print(f"Hash found: {new_block.hash} @ 難度 {self.diff}，耗時: {time_consumed}秒")
        self.chain.append(new_block)  # 將新區塊加進鏈裡
        return self.reward

    def get_balance(self, account):  # 計算帳號餘額(有點暴力)
        balance = 0
        for block in self.chain:  # 檢查鏈內每個區塊
            miner = False  # 紀錄是否為該區塊礦工
            if block.miner == account:
                miner = True
                balance += block.reward  # 挖出區塊獎勵
            for trade in block.trades:  # 計算匯款所造成的金額變動、礦工獲得的手續費
                if miner:
                    balance += trade.fee  # 礦工獲得手續費
                if trade.sender == account:  # 寄送者扣錢
                    balance -= trade.pay
                    balance -= trade.fee  # 手續費由寄款者出
                elif trade.receiver == account:  # 接受者加錢
                    balance += trade.pay
        return balance

    def check(self):  # 檢查是否有hash值不符(遭竄改)
        pre_hash = ''
        for idx,block in enumerate(self.chain):  # 利用enumerate函式，紀錄目前在檢查第幾個區塊
            if self.get_hash(block, block.nonce) != block.hash:  # 本區塊hash值是否相同
                print("Error : Hash值不符!")
                return False
            elif pre_hash != block.pre_hash and idx!=0:  # 因為創世區塊沒有前一個區塊，因此沒有pre_hash，不須檢查pre_hash。
                print("Error : pre_Hash值與前一區塊Hash值不符")  # pre_hash值跟前一個區塊hash值不同
                return False
            pre_hash = block.hash   # 記錄前一個區塊hash值
        print("Hash值正確!")
        return True
    
    def generate_address(self):
        pub, priv = rsa.newkeys(512)  # 生成公私鑰
        pub_key = pub.save_pkcs1()  # 轉成pkcs1形式儲存
        priv_key = priv.save_pkcs1()  # 同上
        pub_key=self.pub_address_reduce(pub_key) # 將無用字元搞掉
        return pub_key, priv_key
    
    def pub_address_reduce(self, pub):
        add = str(pub).replace('\\n','')  # 刪除無用字元
        add = add.replace("b'-----BEGIN RSA PUBLIC KEY-----", '')
        add = add.replace("-----END RSA PUBLIC KEY-----'", '')
        add = add.replace(' ', '')
        print()
        print("地址 :", add)
        print()
        return add
    
    def init_trade(self, sender, receiver, pay, message, fee):  # 初始化一個交易變數
        print()
        if self.get_balance(sender) < pay + fee:  # 判斷餘額是否足夠
            print("餘額不足!")
            print()
            return False
        trade = Trade(sender, receiver, pay, message, fee)  # 生成一個交易變數
        return trade
    
    def sign_trade(self, trade, priv_key):
        priv_pkcs = rsa.PrivateKey.load_pkcs1(priv_key)  # 將私鑰轉為pcks1形式
        trade_str = self.trade_to_str(trade)  # 將交易資料轉為字串
        sign = rsa.sign(trade_str.encode('utf-8'), priv_pkcs, 'SHA-1')  # 利用私鑰(pcks1)簽名
        return sign
    
    def add_trade(self, trade, sign):
        pub_key = '-----BEGIN RSA PUBLIC KEY-----\n'
        pub_key += trade.sender
        pub_key += '\n-----END RSA PUBLIC KEY-----\n'  # 以上三行讓地址符合格式
        pub_key_pkcs = rsa.PublicKey.load_pkcs1(pub_key.encode('utf-8'))  # 將地址回推成公鑰
        trade_str = self.trade_to_str(trade)
        if trade.fee + trade.pay > self.get_balance(trade.sender):  # 判斷餘額是否足夠
            print("沒錢還想轉錢給別人啊?")
            print()
            return False, "Balance not enough!"
        try:  # 嘗試進行驗證，若未通過則報錯至except
            rsa.verify(trade_str.encode('utf-8'), sign, pub_key_pkcs)  # 進行驗證，以公鑰嘗試解密交易上的數位簽名
            print("RSA認證成功，執行交易!")  # 若成功解開則代表公鑰與私鑰匹配，代表為發送者本人簽署的
            self.waiting.append(trade)  # 加到等待中的交易行列裡
            print("交易成功! 剩餘餘額 :", self.get_balance(trade.sender)-trade.fee-trade.pay)
            print()
            return True, "Success!"
        except Exception:
            print("RSA認證未通過，身分不符!")  # 若未成功解開則代表公鑰與私鑰不是同一對，則代表這是非本人簽署(非本人發起的交易)
            print()
            return False, "RSA Verified wrong!"

    def start_socket_server(self):
        t = threading.Thread(target=self.wait_socket_connect)  # 建立wait_socket_connet的多個執行緒，以提升CPU使用效率以及運算速度(建立多個執行緒以同時平行的執行多個程序)
        t.start()

    def wait_socket_connect(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: # 宣告一個TCP的socket，代表網路連接的端點，名為s
            s.bind((self.socket_host, self.socket_port))  # 設置監聽的位置與端口(一個ip(電腦)內有許多port，類似一個海港有許多船位)
            s.listen()  # 設定連接數量上限(此為無上限)
            while True:
                client, addr = s.accept()  # 接收串連，並回傳(client,address)，client存串接對象，addr存連線資訊

                client_handler = threading.Thread(  # 建立接收訊息的多個執行緒
                    target=self.receive_socket_message,  # 執行緒執行的內容目標物為receive_socket_message
                    args=(client, addr)  # 監聽到的格式為(client, addr)
                )
                client_handler.start()  # 執行該執行緒

    def receive_socket_message(self, connection, address):
        with connection:
            print()
            print(f'連接到 : {address}\n')
            while True:
                message = connection.recv(1024)  # 接收訊息(上限1024bytes)
                print()
                print(f"[*] 接收訊息: {message}\n")
                try:
                    parsed_message = pickle.loads(message)  # 嘗試將message反序列化(pares_message為dictionary)
                except Exception:
                    print(f"{message} 無法被反序列化")
                    print()
                if message:  # message有東西
                    if parsed_message["request"] == "get_balance":  # 如果用戶要查看餘額
                        print("開始為用戶取得餘額")
                        print()
                        address = parsed_message["address"]  # 從接收的訊息抓address
                        balance = self.get_balance(address)
                        response = {
                            "address": address,
                            "balance": balance
                        }
                    elif parsed_message["request"] == "trade":  # 要交易
                        print("開始為用戶發起交易\n")
                        new_trade = parsed_message["data"]
                        result, result_message = self.add_trade(new_trade, parsed_message["sign"])  # result為從add_trade return 回來的bool(True or False)，result_message為結束前的print(RSA不符or交易成功)
                        response = {
                            "result": str(result),
                            "result_message": str(result_message)
                        }
                    elif parsed_message["request"] == "earn":  # 賺錢
                        print("開始使用戶成為礦工\n")
                        addr = parsed_message["address"]
                        earn=self.mine_block(addr)
                        response = {
                            "result": "success",
                            "result_message": "earn "+str(earn)+" money"
                        }
                    else:
                        response = {
                            "message": "unknown command."  # 未知請求(非交易或查餘額)
                        }
                    response_bytes = str(response).encode('utf8')  # 將response(dictionary)轉成string，再轉換成位元組串列，才能用socket傳送
                    connection.sendall(response_bytes)  # 將response_bytes的內容全部傳回客戶端(sendall與send不同之處在於sendall保證完整性，即使需要多次傳輸也會將內容全部傳回)



if __name__ == '__main__':
    block = BlockChain()  # 建造一個鏈
    block.create_genesis_block()  # 創建創世區塊

    print()
    print("初始難度 :", block.diff)
    print("設定挖掘一區塊平均耗時上限 :", block.max_time, "，平均耗時下限 :", block.min_time, "。每挖掘", block.adjust_diff, "次調整一次難度。")
    print("挖掘出一個區塊的獎勵為 :", block.reward, "元")

    addr, priv = block.generate_address()  # 產生公私鑰地址

    block.mine_block(addr)

    while(True):
            block.mine_block(addr)
            time.sleep(1)

    block.check()  # 檢查hash值
    
    print("插入假交易")
    fake_trade = Trade('test123', 'address', 100, 1, 50)  # 製造假交易
    block.chain[1].trades.append(fake_trade)  # 插入假交易

    if not block.check() : #檢查hash值
        print()
        print("---------------------------------------------------")
        print("ERROR!!!")
        print("區塊鏈遭到竄改!")
        print("---------------------------------------------------")
        print()

    print("Pomelo0411餘額 :", block.get_balance(addr))  # 輸出餘額