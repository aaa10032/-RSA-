import random
import math
import base64

# 汉字歌词映射表 (完全自定义的替换规则)
LYRIC_MAP = {
    '哈': 'A', '基': 'B', '咪': 'C', '南': 'D', '北': 'E',
    '绿': 'F', '多': 'G', '阿': 'H', '西': 'I', '噶': 'J',
    '雅': 'K', '酷': 'L', '奶': 'M', '农': 'N', '叮': 'O',
    '咚': 'P', '鸡': 'Q', '曼': 'R', '波': 'S', '亚': 'T',
    '不': 'U', '有': 'V', '曹': 'W', '吗': 'X', '吉': 'Y',
    '利': 'Z', '一': '0', '端': '1', '待': '2', '哇': '3',
    '呀': '4', '摸': '5', '，': '6', '。': '7', ' ': '8',
    '\n': '9', '啊': '+', '雅酷': '/', '南北': '=', '^': '^'
}

# 添加缺失的base64字符映射
BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
# 为每个base64字符分配一个汉字，如果LYRIC_MAP没有就补充
SUPPLEMENT_MAP = {
    'b': '比', 'c': '此', 'd': '的', 'f': '发', 'g': '个',
    'h': '和', 'i': '是', 'j': '就', 'k': '看', 'l': '了',
    'm': '没', 'n': '你', 'o': '哦', 'p': '平', 'q': '去',
    'r': '人', 's': '是', 't': '他', 'u': '有', 'v': '我',
    'w': '我', 'x': '下', 'y': '有', 'z': '在', 'a': '啊',
    'e': '饿'
}

# 创建完整的映射表
FULL_MAP = LYRIC_MAP.copy()
for i, char in enumerate(BASE64_CHARS):
    if char not in [v for v in FULL_MAP.values()]:
        # 为这个字符找一个汉字
        for hanzi, val in FULL_MAP.items():
            if val == '8' and char == ' ':  # 空格
                break
        # 如果还是没找到，从补充映射中取
        if char.lower() in SUPPLEMENT_MAP and char not in [v for v in FULL_MAP.values()]:
            # 找一个未使用的汉字
            for hanzi in SUPPLEMENT_MAP.values():
                if hanzi not in FULL_MAP:
                    FULL_MAP[hanzi] = char
                    break

# 创建反向映射
REVERSE_MAP = {}
for hanzi, b64_char in FULL_MAP.items():
    if b64_char not in REVERSE_MAP:
        REVERSE_MAP[b64_char] = hanzi
    # 处理特殊情况：一个base64字符可能对应多个汉字，我们取第一个
    elif isinstance(REVERSE_MAP[b64_char], str):
        # 转换为列表存储多个映射
        REVERSE_MAP[b64_char] = [REVERSE_MAP[b64_char], hanzi]
    else:
        REVERSE_MAP[b64_char].append(hanzi)

# 简化REVERSE_MAP，对于多映射只取第一个
SIMPLE_REVERSE_MAP = {}
for b64_char, hanzi in REVERSE_MAP.items():
    if isinstance(hanzi, list):
        SIMPLE_REVERSE_MAP[b64_char] = hanzi[0]
    else:
        SIMPLE_REVERSE_MAP[b64_char] = hanzi

# 核心RSA类
class RSA_Cipher:
    def __init__(self, bit_length=256):  # 默认256位，可改为2048
        self.bit_length = bit_length
        self.p = self.q = self.n = self.phi = self.e = self.d = None
        
    def is_prime(self, num, tests=20):
        """Miller-Rabin素数检测"""
        if num < 2: 
            return False
        # 检查小素数
        small_primes = [2,3,5,7,11,13,17,19,23,29,31,37]
        for p in small_primes:
            if num % p == 0:
                return num == p
        # 写n-1 = d * 2^s
        s, d = 0, num-1
        while d % 2 == 0:
            s += 1
            d //= 2
        # Miller-Rabin测试
        for _ in range(tests):
            a = random.randint(2, num-2)
            x = pow(a, d, num)
            if x == 1 or x == num-1:
                continue
            for _ in range(s-1):
                x = (x * x) % num
                if x == num-1:
                    break
            else:
                return False
        return True
    
    def gen_prime(self):
        """生成大素数"""
        while True:
            p = random.getrandbits(self.bit_length//2)
            # 确保是奇数且足够大
            p |= (1 << (self.bit_length//2 - 1)) | 1
            if self.is_prime(p):
                return p
    
    def gcd_extended(self, a, b):
        """扩展欧几里得求逆元"""
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.gcd_extended(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y
    
    def gen_keys(self):
        """生成RSA密钥对"""
        self.p = self.gen_prime()
        self.q = self.gen_prime()
        while self.p == self.q:
            self.q = self.gen_prime()
        
        self.n = self.p * self.q
        self.phi = (self.p-1) * (self.q-1)
        
        # 选公钥e
        self.e = 65537
        while math.gcd(self.e, self.phi) != 1:
            self.e += 2
        
        # 计算私钥d
        _, d, _ = self.gcd_extended(self.e, self.phi)
        self.d = d % self.phi
        
        return {
            'public': (self.e, self.n),
            'private': (self.d, self.n)
        }
    
    def encrypt_num(self, m, e, n):
        """加密数字"""
        return pow(m, e, n)
    
    def decrypt_num(self, c, d, n):
        """解密数字"""
        return pow(c, d, n)
    
    def text_to_lyric(self, text):
        """将普通文本转成哈基咪歌词密文"""
        # 先base64编码确保二进制安全
        try:
            b64 = base64.b64encode(text.encode()).decode()
        except:
            # 如果已经是base64，直接使用
            b64 = text
        
        lyric = []
        for char in b64:
            if char in SIMPLE_REVERSE_MAP:
                lyric.append(SIMPLE_REVERSE_MAP[char])
            else:
                # 不在映射表的字符用空格代替
                lyric.append(' ')
        
        # 按段落分组
        lines = []
        current_line = []
        line_length = 0
        for word in lyric:
            if word != ' ':
                current_line.append(word)
                line_length += 1
                if line_length >= 8:  # 每行8个汉字
                    lines.append(''.join(current_line))
                    current_line = []
                    line_length = 0
        
        if current_line:
            lines.append(''.join(current_line))
        
        # 插入固定歌词增强关联性
        result = []
        for i, line in enumerate(lines):
            result.append(line)
            if i % 3 == 0:
                result.append("哈基咪摸南北绿多")
            elif i % 3 == 1:
                result.append("叮咚鸡曼波亚不亚不有")
            elif i % 3 == 2:
                result.append("吗吉利哇呀曼波")
        
        # 添加开头和结尾的固定歌词
        final_result = ["哈基咪南北绿多，阿西噶阿西",
                       "阿西哈雅酷奶农，哈基咪哈基"]
        final_result.extend(result)
        final_result.extend(["哈基咪哈基咪摸南，北绿多",
                           "亚不亚不有，有待有待",
                           "啊，曼波，啊，吗吉利"])
        
        return '\n'.join(final_result)
    
    def lyric_to_text(self, lyric):
        """将歌词密文转回普通文本"""
        # 分割行
        lines = lyric.strip().split('\n')
        
        # 移除固定歌词行（开头2行和结尾3行）
        if len(lines) > 5:
            lines = lines[2:-3]
        
        # 进一步移除固定插入的歌词
        filtered = []
        skip_lines = {"哈基咪摸南北绿多", "叮咚鸡曼波亚不亚不有", "吗吉利哇呀曼波"}
        for line in lines:
            if line not in skip_lines:
                filtered.append(line)
        
        # 转换回base64
        b64_chars = []
        for line in filtered:
            for char in line:
                # 查找这个汉字对应的base64字符
                found = False
                for b64_char, hanzi in SIMPLE_REVERSE_MAP.items():
                    if hanzi == char:
                        b64_chars.append(b64_char)
                        found = True
                        break
                if not found:
                    # 尝试在FULL_MAP中查找
                    for hanzi_key, b64_val in FULL_MAP.items():
                        if hhanzi_key == char:
                           b64_chars.append(b64_val)
                           found = True
                           break
                if not found:
                    b64_chars.append(' ')  # 空格
        
        b64_str = ''.join(b64_chars).replace(' ', '')
        
        # 清理无效字符
        clean_b64 = ''
        for char in b64_str:
            if char in BASE64_CHARS:
                clean_b64 += char
        
        try:
            # 尝试解码
            decoded = base64.b64decode(clean_b64).decode('utf-8', errors='ignore')
            return decoded
        except:
            # 如果解码失败，返回原始base64
            return clean_b64
    
    def encrypt(self, plaintext, e=None, n=None):
        """完整加密流程"""
        # 验证n值有效性
        if n is not None and n < 2:
            print("警告：n值太小，使用自动生成密钥")
            e = n = None
        
        if e is None or n is None:
            keys = self.gen_keys()
            e, n = keys['public']
            d = keys['private'][0]
            print(f"【自动生成密钥】\n公钥(e,n): ({e},\n{n})\n私钥(d): {d}")
        else:
            print(f"【使用自定义公钥】\n公钥(e,n): ({e}, {n})")
        
        # RSA加密每个字符的Unicode值（简化版本，实际应分块加密）
        encrypted_nums = []
        block_size = (n.bit_length() // 8) - 1  # 安全块大小
        
        # 分块加密
        for i in range(0, len(plaintext), block_size):
            block = plaintext[i:i+block_size]
            # 将块转换为大整数
            m = 0
            for j, char in enumerate(block):
                m = (m << 8) | ord(char)
            
            # 加密这个块
            c = self.encrypt_num(m, e, n)
            encrypted_nums.append(str(c))
        
        # 用"|"分隔密文块
        num_str = '|'.join(encrypted_nums)
        
        # 转换为歌词密文
        lyric_cipher = self.text_to_lyric(num_str)
        
        return lyric_cipher
    
    def decrypt(self, lyric_cipher, d=None, n=None):
        """完整解密流程"""
        # 先转回数字字符串
        num_str = self.lyric_to_text(lyric_cipher)
        
        if d is None or n is None:
            return "需要提供私钥(d,n)"
        
        # 解析数字密文
        try:
            encrypted_nums = [int(x) for x in num_str.split('|') if x]
        except:
            return "密文格式错误"
        
        # RSA解密每个块
        decrypted_blocks = []
        for c in encrypted_nums:
            m = self.decrypt_num(c, d, n)
            
            # 将大整数转换回字符串
            block_chars = []
            while m > 0:
                block_chars.insert(0, chr(m & 0xFF))
                m >>= 8
            decrypted_blocks.append(''.join(block_chars))
        
        return ''.join(decrypted_blocks)

# 主程序
def main():
    print("="*50)
    print("哈基咪RSA加密系统")
    print("="*50)
    
    # 选择密钥长度
    bit_choice = input("选择密钥长度 (1=256位 2=512位 3=1024位 4=2048位):\n>> ").strip()
    bit_options = {'1': 256, '2': 512, '3': 1024, '4': 2048}
    bit_length = bit_options.get(bit_choice, 256)
    
    cipher = RSA_Cipher(bit_length=bit_length)
    
    mode = input("请选择模式: 1=加密 2=解密\n>> ").strip()
    
    if mode == "1":
        print("\n输入要加密的明文 (支持中文/英文/特殊字符):")
        plaintext = input(">> ")
        
        key_choice = input("\n使用自定义公钥? (y=是, 其他=自动生成)\n>> ").lower()
        if key_choice == 'y':
            try:
                e = int(input("输入公钥e值 (推荐65537):\n>> "))
                n = int(input("输入模数n值 (必须为大整数):\n>> "))
                if n < 100:
                    print("n值太小，使用自动生成")
                    e = n = None
            except:
                print("输入错误，使用自动生成密钥")
                e = n = None
        else:
            e = n = None
        
        print("\n加密中...")
        ciphertext = cipher.encrypt(plaintext, e, n)
        
        print("\n" + "="*50)
        print("【生成的歌词密文】")
        print(ciphertext)
        print("="*50)
        
        if e is None and hasattr(cipher, 'd'):
            print(f"\n【保存以下密钥用于解密】")
            print(f"私钥d: {cipher.d}")
            print(f"模数n: {cipher.n}")
            print(f"密钥长度: {bit_length}位")
        
    elif mode == "2":
        print("\n粘贴歌词密文 (包含哈基咪等歌词):")
        ciphertext_lines = []
        print("(输入空行结束)")
        while True:
            line = input()
            if line == "":
                break
            ciphertext_lines.append(line)
        ciphertext = '\n'.join(ciphertext_lines)
        
        try:
            d = int(input("\n输入私钥d值:\n>> "))
            n = int(input("输入模数n值:\n>> "))
        except:
            print("密钥输入错误")
            return
        
        print("\n解密中...")
        plaintext = cipher.decrypt(ciphertext, d, n)
        
        print("\n" + "="*50)
        print("【解密结果】")
        print(plaintext)
        print("="*50)
    
    else:
        print("无效选择")

if __name__ == "__main__":
    main()