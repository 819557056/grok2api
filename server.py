from fastapi import FastAPI, HTTPException, Depends, Query, Body
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import time
import json
import os
from datetime import datetime
import logging
from faker import Faker

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("cf5s-server")

app = FastAPI(title="Cloudflare 5s Bypass API")

# 初始化Faker
fake = Faker()

# 默认管理员密码，如果环境变量未设置则使用此密码
DEFAULT_ADMIN_PASSWORD = "your_admin_password"

# 读取管理员密码环境变量
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
logger.info(f"当前使用的管理员密码来源: {'环境变量' if ADMIN_PASSWORD != DEFAULT_ADMIN_PASSWORD else '默认值'}")

# 存储配置和数据的文件路径
CONFIG_FILE = "cf_config.json"
COOKIES_FILE = "cf_cookies.json"  # 保留用于兼容性，实际数据会同时存储在CONFIG_FILE中

# 默认配置
DEFAULT_CONFIG = {
    "url": "https://chatgpt.com",
    "need_update": {
        "proxy_url_pool": [],
        "user_agent_list": [],
        "user_agent": None
    },
    "exist_data_list": []
}

# 确保配置文件存在
if not os.path.exists(CONFIG_FILE):
    with open(CONFIG_FILE, "w") as f:
        json.dump(DEFAULT_CONFIG, f, indent=4)
    logger.info(f"创建配置文件: {CONFIG_FILE}")

# 历史兼容性：如果cookies文件存在但配置文件的exist_data_list为空，则导入cookies
if os.path.exists(COOKIES_FILE):
    try:
        with open(COOKIES_FILE, "r") as f:
            cookies = json.load(f)
        
        if cookies:
            # 将cookies导入到配置文件中
            config = DEFAULT_CONFIG
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
            
            if not config.get("exist_data_list"):
                config["exist_data_list"] = cookies
                with open(CONFIG_FILE, "w") as f:
                    json.dump(config, f, indent=4)
                logger.info(f"已将历史Cookie数据导入到配置文件中")
    except Exception as e:
        logger.error(f"导入历史Cookie数据失败: {str(e)}")
else:
    # 创建一个空的cookies文件用于兼容性
    with open(COOKIES_FILE, "w") as f:
        json.dump([], f, indent=4)
    logger.info(f"创建空的Cookie文件用于兼容性: {COOKIES_FILE}")

class CookieData(BaseModel):
    user_agent: str
    cookies: List[Dict[str, Any]]
    proxy_url: Optional[str] = None
    update_time: int
    expire_time: int

def load_config():
    """加载配置文件"""
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"加载配置文件失败: {str(e)}")
        return DEFAULT_CONFIG

def save_config(config):
    """保存配置文件"""
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=4)
    except Exception as e:
        logger.error(f"保存配置文件失败: {str(e)}")

def load_cookies():
    """加载Cookie文件（仅用于兼容性）"""
    try:
        with open(COOKIES_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"加载Cookie文件失败: {str(e)}")
        return []

def save_cookies(cookies):
    """保存Cookie文件（仅用于兼容性）"""
    try:
        with open(COOKIES_FILE, "w") as f:
            json.dump(cookies, f, indent=4)
    except Exception as e:
        logger.error(f"保存Cookie文件失败: {str(e)}")

def generate_random_user_agents(count=10):
    """生成随机的User-Agent字符串"""
    user_agents = []
    for _ in range(count):
        user_agents.append(fake.user_agent())
    return user_agents

def is_cookie_expired(cookie, user_agent, proxy_url=None):
    """判断Cookie是否过期"""
    current_time = int(time.time())
    if proxy_url is not None:
        return (cookie.get("proxy_url") != proxy_url or 
                cookie.get("user_agent") != user_agent or 
                current_time >= cookie.get("expire_time", 0))
    else:
        return (cookie.get("user_agent") != user_agent or 
                current_time >= cookie.get("expire_time", 0))

def verify_admin_password(admin_password: str = Query(None)):
    """验证管理员密码"""
    if not admin_password:
        logger.warning("请求缺少admin_password参数")
        raise HTTPException(status_code=403, detail="Missing admin password")
    
    if admin_password != ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 提供的密码与系统密码不匹配")
        raise HTTPException(status_code=403, detail="Invalid admin password")
    
    return True

@app.get("/api/get-cf-list")
async def get_cf_list(admin_password: Optional[str] = Query(None)):
    """获取需要更新的代理和用户代理列表"""
    logger.info(f"收到获取配置请求")
    if admin_password:
        logger.info(f"提供的admin_password长度: {len(admin_password)}")
    else:
        logger.warning("请求中没有提供admin_password参数")
    
    # 为了调试，暂时注释掉密码验证逻辑
    # 验证密码
    # verify_admin_password(admin_password)
    
    # 直接使用默认密码进行比较
    if admin_password != DEFAULT_ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 接收到的密码与默认密码不匹配")
        # 为了调试，暂时不抛出异常
        logger.info(f"接收到的密码: {admin_password}, 默认密码: {DEFAULT_ADMIN_PASSWORD}")
    
    # 加载配置
    config = load_config()
    
    # 验证和清理exist_data_list中的数据
    valid_cookies = []
    for cookie in config.get("exist_data_list", []):
        # 检查必要字段是否存在
        if "user_agent" in cookie and "cookies" in cookie and "expire_time" in cookie:
            valid_cookies.append(cookie)
        else:
            logger.warning(f"发现无效的cookie格式，已忽略: {cookie}")
    
    # 更新配置中的有效cookie
    config["exist_data_list"] = valid_cookies
    
    # 检查哪些配置需要更新
    need_update = {
        "proxy_url_pool": [],
        "user_agent_list": [],
        "user_agent": config["need_update"].get("user_agent")
    }
    
    # 如果user_agent_list为空，使用faker生成10个随机user-agent
    if not config["need_update"].get("user_agent_list"):
        logger.info("User-Agent列表为空，自动生成10个随机User-Agent")
        need_update["user_agent_list"] = generate_random_user_agents(10)
        # 保存生成的User-Agent到配置中
        config["need_update"]["user_agent_list"] = need_update["user_agent_list"]
        save_config(config)
    else:
        need_update["user_agent_list"] = config["need_update"].get("user_agent_list", [])
    
    # 检查代理池中的代理是否需要更新
    for proxy_url in config["need_update"].get("proxy_url_pool", []):
        for user_agent in need_update["user_agent_list"]:
            need_update_for_this_pair = True
            for cookie in valid_cookies:
                if (cookie.get("proxy_url") == proxy_url and 
                    cookie.get("user_agent") == user_agent and 
                    int(time.time()) < cookie.get("expire_time", 0)):
                    need_update_for_this_pair = False
                    break
            
            if need_update_for_this_pair and proxy_url not in need_update["proxy_url_pool"]:
                need_update["proxy_url_pool"].append(proxy_url)
    
    # 检查用户代理是否需要更新
    user_agents_to_update = []
    for user_agent in need_update["user_agent_list"]:
        need_update_for_this_ua = True
        for cookie in valid_cookies:
            if (cookie.get("proxy_url") is None and 
                cookie.get("user_agent") == user_agent and 
                int(time.time()) < cookie.get("expire_time", 0)):
                need_update_for_this_ua = False
                break
        
        if need_update_for_this_ua and user_agent not in user_agents_to_update:
            user_agents_to_update.append(user_agent)
    
    # 为了兼容客户端，我们保留原来的完整user_agent_list
    user_agent_list_full = need_update["user_agent_list"].copy()
    
    # 只更新需要更新的user_agent，但保留完整列表的引用
    need_update["user_agent_list"] = user_agents_to_update
    
    # 更新配置
    config["need_update"] = need_update
    save_config(config)
    
    # 为了兼容，将数据也同步到cookies文件
    save_cookies(valid_cookies)
    
    # 构建响应数据
    response_data = dict(config)
    response_data["need_update"]["user_agent_list_full"] = user_agent_list_full
    
    logger.info(f"返回配置信息: url={response_data['url']}, need_update.proxy_url_pool数量={len(need_update['proxy_url_pool'])}, need_update.user_agent_list数量={len(need_update['user_agent_list'])}")
    
    return response_data

@app.post("/api/set-cf-cookie")
async def set_cf_cookie(cookie_data: CookieData, admin_password: Optional[str] = Query(None)):
    """设置新的Cloudflare cookie"""
    logger.info(f"收到设置Cookie请求")
    if admin_password:
        logger.info(f"提供的admin_password长度: {len(admin_password)}")
    else:
        logger.warning("请求中没有提供admin_password参数")
    
    # 为了调试，暂时注释掉密码验证逻辑
    # 验证密码
    # verify_admin_password(admin_password)
    
    # 直接使用默认密码进行比较
    if admin_password != DEFAULT_ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 接收到的密码与默认密码不匹配")
        # 为了调试，暂时不抛出异常
        logger.info(f"接收到的密码: {admin_password}, 默认密码: {DEFAULT_ADMIN_PASSWORD}")
    
    # 加载当前配置和Cookie列表
    config = load_config()
    cookies = config.get("exist_data_list", [])
    
    # 检查是否已存在相同条件的cookie
    found = False
    for i, cookie in enumerate(cookies):
        if cookie_data.proxy_url is not None:
            if (cookie.get("proxy_url") == cookie_data.proxy_url and 
                cookie.get("user_agent") == cookie_data.user_agent):
                cookies[i] = cookie_data.dict()
                found = True
                break
        else:
            if (cookie.get("proxy_url") is None and 
                cookie.get("user_agent") == cookie_data.user_agent):
                cookies[i] = cookie_data.dict()
                found = True
                break
    
    if not found:
        cookies.append(cookie_data.dict())
    
    # 更新配置文件中的exist_data_list
    config["exist_data_list"] = cookies
    save_config(config)
    
    # 为了兼容性，也保存到cookies文件
    save_cookies(cookies)
    
    logger.info(f"成功保存Cookie: user_agent={cookie_data.user_agent}, proxy_url={cookie_data.proxy_url}")
    
    return {"status": "success", "message": "Cookie saved successfully"}

@app.post("/api/update-config")
async def update_config(config_data: dict = Body(...), admin_password: Optional[str] = Query(None)):
    """更新配置"""
    logger.info(f"收到更新配置请求")
    if admin_password:
        logger.info(f"提供的admin_password长度: {len(admin_password)}")
    else:
        logger.warning("请求中没有提供admin_password参数")
    
    # 为了调试，暂时注释掉密码验证逻辑
    # 验证密码
    # verify_admin_password(admin_password)
    
    # 直接使用默认密码进行比较
    if admin_password != DEFAULT_ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 接收到的密码与默认密码不匹配")
        # 为了调试，暂时不抛出异常
        logger.info(f"接收到的密码: {admin_password}, 默认密码: {DEFAULT_ADMIN_PASSWORD}")
    
    current_config = load_config()
    
    # 更新配置
    if "url" in config_data:
        current_config["url"] = config_data["url"]
    
    if "need_update" in config_data:
        if "proxy_url_pool" in config_data["need_update"]:
            current_config["need_update"]["proxy_url_pool"] = config_data["need_update"]["proxy_url_pool"]
        
        if "user_agent_list" in config_data["need_update"]:
            current_config["need_update"]["user_agent_list"] = config_data["need_update"]["user_agent_list"]
        
        if "user_agent" in config_data["need_update"]:
            current_config["need_update"]["user_agent"] = config_data["need_update"]["user_agent"]
    
    save_config(current_config)
    logger.info(f"成功更新配置")
    
    return {"status": "success", "message": "Config updated successfully"}

@app.get("/api/debug")
async def debug_info():
    """返回调试信息，帮助排查环境变量问题"""
    env_vars = {key: value for key, value in os.environ.items()}
    
    # 为了安全，隐藏敏感信息
    if "ADMIN_PASSWORD" in env_vars:
        env_vars["ADMIN_PASSWORD"] = f"{'*' * (len(env_vars['ADMIN_PASSWORD']) - 4)}{env_vars['ADMIN_PASSWORD'][-4:]}"
    
    return {
        "system_info": {
            "python_version": os.sys.version,
            "platform": os.sys.platform,
            "cwd": os.getcwd()
        },
        "environment_variables": env_vars,
        "admin_password_source": "环境变量" if ADMIN_PASSWORD != DEFAULT_ADMIN_PASSWORD else "默认值",
        "files": {
            "config_file_exists": os.path.exists(CONFIG_FILE),
            "cookies_file_exists": os.path.exists(COOKIES_FILE)
        }
    }

if __name__ == "__main__":
    import uvicorn
    logger.info(f"启动服务，监听地址: 0.0.0.0:8000")
    logger.info(f"管理员密码来源: {'环境变量' if ADMIN_PASSWORD != DEFAULT_ADMIN_PASSWORD else '默认值'}")
    uvicorn.run(app, host="0.0.0.0", port=8000) 