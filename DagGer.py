import re #正则库
import time
import requests #爬虫
import random
import json
import threading #线程
from concurrent.futures import ThreadPoolExecutor #多线程

#中断程序
import signal, os, sys
def force_exit(signum, frame):
    os.write(1, b"\n[!] signal caught\n")  # 不用 print，直接写 fd，最底层的输出
    os._exit(1)

signal.signal(signal.SIGINT, force_exit)
signal.signal(signal.SIGTERM, force_exit)

print("已注册信号处理，PID =", os.getpid())

# 类外全局，供所有方法用
session = requests.Session()
_adapter = requests.adapters.HTTPAdapter(pool_connections=500, pool_maxsize=500)
session.mount('https://', _adapter)
session.mount('http://', _adapter)


class DagGer:
    print('''\033[34m
      ______       ____        _____       _____     _____   ______    
    (_  __ \     (    )      / ___ \     / ___ \   / ___/  (   __ \   
      ) ) \ \    / /\ \     / /   \_)   / /   \_) ( (__     ) (__) )  
     ( (   ) )  ( (__) )   ( (  ____   ( (  ____   ) __)   (    __/   
      ) )  ) )   )    (    ( ( (__  )  ( ( (__  ) ( (       ) \ \  _  
     / /__/ /   /  /\  \    \ \__/ /    \ \__/ /   \ \___  ( ( \ \_)) 
    (______/   /__(  )__\    \____/      \____/     \____\  )_) \__/  \033[0m\033[31m
    [*]Version:测试
    [*]一款用于对主域名进行信息收集的单兵工具
    [*]作者:CatFl0g
    [*]GitHub地址:\033[0m''')

    #主域名
    while True:
        url = input('[*]请输入主域名(示例:example.com):')
        if url == ' ' or url == '':
            print('请输入正确的主域名')
            continue
        break
    print(f'您输入的主域名为{url}')
    # user-agent的随机字典
    Users_Agent_list = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0',
        'Mozilla/5.0 (Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0',
        'Mozilla/5.0 (Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:57.0) Gecko/20100101 Firefox/57.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:58.0) Gecko/20100101 Firefox/58.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36'
    ]

    # 存活子域名存放位置
    live_sub = set()

    #线程锁
    print_lock = threading.Lock()
    # 随机的User-Agent
    def user_agent(self):
        return {'User-Agent': random.choice(self.Users_Agent_list)}


    #----------------------------------------备案查询-------------------------------------------

    def record(self):
        record_url = 'https://www.huodaidaohang.cn/commontools/php/apihz.php?action=icp-query&domain=' + self.url
        try:
            response = session.get(url=record_url, headers=self.user_agent())
            print('备案查询结果:',json.loads(response.text))
        except requests.RequestException:
            print('备案查询失败')


    #----------------------------------------子域名扫描------------------------------------------

        #--------调度
    def scan_subname(self):
        print('\n')
        print(f'\033[34m--------------------------子域名扫描{self.url}------------------------------------\033[0m')
        # 访问字典
        with open(r'Dictionary/subnames-9.5w.txt', 'r', encoding='utf-8') as f:
            subname_list = f.read().splitlines()

        os.makedirs('子域名', exist_ok=True)
        with ThreadPoolExecutor(max_workers=100) as executor:
            for subname in subname_list:
                true_url = f'https://{subname}.{self.url}'
                executor.submit(self.dns,subname, true_url) # 提交 dns，传两个参数


        #------子域名检测
    def dns(self,subname,true_url):
        # 检测存活子域名是否重复
        if true_url in self.live_sub:
            return
        try:
                response = session.get(true_url, headers=self.user_agent(), timeout=3)
                response.encoding = 'utf-8'
                #线程锁
                with self.print_lock:
                    print(f'\033[32m url: {true_url} -> 响应码: [{response.status_code}]  -> 标题: {re.findall("<title>(.*?)</title>", response.text)} -> 存活\033[0m')

                self.live_sub.add(true_url)
                #写入对应的文件
                with open(f'子域名/{self.url}.txt','a+', encoding='utf-8') as f:
                    f.write(f'{true_url} -> 标题:{re.findall("<title>(.*?)</title>",response.text)}' + '\n')
        except requests.RequestException:
                pass
                # print(f'url: {true_url} -> 标题: {re.findall("<title>(.*?)</title>", response.text)} -> 死亡')


#-------------------------------------------目录扫描-----------------------------------------------
    def contents(self,live_sub): #目录扫描
        print('\n')
        #live_sub = "https://www.baidu.com/"
        host = live_sub.replace("https://","").replace("http://","").rstrip("/")
        #host = "www.baidu.com"
        print(f"\033[34m----------------------------目录扫描:{host}-----------------------------------------\033[0m")
        api_path = set() #设置空列表
        #读取目录字典
        mulu = None
        for enc in ('UTF-8' , 'utf-8-sig' , 'gbk' , 'gb18030'):#尝试多种编码
            try:
                with open(r'Dictionary/all.txt', 'r', encoding=enc) as f:
                    mulu = f.read().splitlines()
                break
            except UnicodeDecodeError:
                continue
            except FileNotFoundError:
                print("\033[31m all.txt 不存在 \033[0m")
                return
        #所有编码错误
        if mulu is None:
            print('\033[31m all.txt 读取失败：所有编码均无法解码 \033[0m')
            return
        os.makedirs('目录扫描结果', exist_ok=True)
        os.makedirs(f'目录扫描结果/{self.url}', exist_ok=True)
        #路径请求
        def scan_one(path):
            path = path.strip()
            if not path:
                return
            mulu_url = f"https://{host}/{path.lstrip('/')}"

            if mulu_url.endswith('/'):
                new_path_url = mulu_url
            else:
                new_path_url = mulu_url + '/'
            # 去重
            if new_path_url in api_path:
                return
            api_path.add(new_path_url)
            try:
                response = session.get(url=new_path_url, headers=self.user_agent(), timeout=3)
                response.encoding = 'utf-8'
                print(f'响应码:[{response.status_code}] -> url:{new_path_url}')
                with open(f'目录扫描结果/{self.url}/{host}.txt','a+', encoding='utf-8') as f:
                    f.write(f'响应码:[{response.status_code}] -> url:{new_path_url}' + '\n')
            except requests.RequestException:
                pass
        with ThreadPoolExecutor(max_workers=50) as ex:
            ex.map(scan_one, mulu)



#-------------------------------------------控制台----------------------------------------------------------
if __name__ == '__main__':
    dagger = DagGer()
    dagger.record()
    dagger.scan_subname()
    #让目录扫描从"一个域名接一个域名"变成"10 个域名同时扫"
    with ThreadPoolExecutor(max_workers=10) as ex:
        ex.map(dagger.contents, list(dagger.live_sub))