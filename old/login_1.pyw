# 使用Selenium自动完成浏览器操作，简单粗暴，但效率偏低下
# 需要下载对应版本的chromedriver.exe，并将其路径添加到环境变量中
# 请确保已安装selenium库和win10toast库
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from win10toast import ToastNotifier
import time
import os

#根据自己的需要，决定是否修改提示图标
success_icon = None  # 替换为你的图标路径
false_icon = None

# 校园网登录页面 URL
url = 'https://tree.buct.edu.cn'

# 初始化 WebDriver（以 Chrome 为例）
driver = webdriver.Chrome()  # 如果使用 Firefox 则替换为 webdriver.Firefox()

# 打开校园网登录页面
driver.get(url)

# 找到并填写用户名和密码
username = 'test1'  # 替换为你的用户名
password = 'test2'  # 替换为你的密码

# 根据实际网页结构填入字段
username_field = driver.find_element(By.ID, 'username')  # 用户名输入框的 ID
password_field = driver.find_element(By.ID, 'password')  # 密码输入框的 ID

username_field.send_keys(username)
password_field.send_keys(password)

# 自动点击登录按钮
login_button = driver.find_element(By.ID, 'login-account')  # 登录按钮的 ID
login_button.click()

# 等待页面加载完成
time.sleep(2)  # 等待页面响应，具体时间可根据网络速度调整

# 检查是否登录成功
if "btn-logout" in driver.page_source:
    driver.quit() # 关闭浏览器
    ToastNotifier().show_toast(title = "登录成功",
               msg = "校园网状态",
               icon_path = success_icon,
               duration = 3,  # 显示时长
               threaded = False)  # 阻塞线程
    os._exit(0) # 退出程序，返回状态码0

else:
    driver.quit() 
    ToastNotifier().show_toast(title = "登录失败",
               msg = "校园网状态",
               icon_path = false_icon,
               duration = 3,
               threaded = False) 
    os._exit(0)
