import json
import os

def get_cf_clearance_value():
    """
    从cf_config.json文件中获取exist_data_list中的cf_clearance的value值
    
    Returns:
        list: 包含所有找到的cf_clearance值的列表
    """
    config_file = "data/cf_config.json"
    cf_clearance_values = []
    
    # 检查文件是否存在
    if not os.path.exists(config_file):
        print(f"配置文件 {config_file} 不存在")
        return cf_clearance_values
    
    try:
        # 读取配置文件
        with open(config_file, "r") as f:
            config = json.load(f)
        
        # 遍历exist_data_list中的每条数据
        for data in config.get("exist_data_list", []):
            # 遍历该数据中的cookies
            for cookie in data.get("cookies", []):
                # 如果找到cf_clearance
                if cookie.get("name") == "cf_clearance":
                    cf_clearance_values.append(cookie.get("value"))
                    break
                    
        return cf_clearance_values
    
    except Exception as e:
        print(f"获取cf_clearance失败: {str(e)}")
        return cf_clearance_values


def delete_data_by_cf_clearance(cf_clearance_value):
    """
    根据cf_clearance的值删除exist_data_list中匹配的数据
    
    Args:
        cf_clearance_value (str): 要匹配的cf_clearance值
        
    Returns:
        bool: 如果成功删除则返回True，否则返回False
    """
    config_file = "data/cf_config.json"
    cookies_file = "data/cf_cookies.json"  # 兼容性考虑
    
    # 检查文件是否存在
    if not os.path.exists(config_file):
        print(f"配置文件 {config_file} 不存在")
        return False
    
    try:
        # 读取配置文件
        with open(config_file, "r") as f:
            config = json.load(f)
        
        original_length = len(config.get("exist_data_list", []))
        new_data_list = []
        
        # 遍历exist_data_list，保留不匹配的数据
        for data in config.get("exist_data_list", []):
            should_keep = True
            
            # 遍历该数据中的cookies
            for cookie in data.get("cookies", []):
                # 如果找到匹配的cf_clearance，标记为不保留
                if cookie.get("name") == "cf_clearance" and cookie.get("value") == cf_clearance_value:
                    should_keep = False
                    break
            
            # 如果没有匹配到，保留该数据
            if should_keep:
                new_data_list.append(data)
        
        # 用过滤后的列表替换原来的exist_data_list
        config["exist_data_list"] = new_data_list
        
        # 保存回配置文件
        with open(config_file, "w") as f:
            json.dump(config, f, indent=4)
        
        # 为了兼容性，也更新cookies文件
        if os.path.exists(cookies_file):
            try:
                with open(cookies_file, "w") as f:
                    json.dump(new_data_list, f, indent=4)
            except Exception as e:
                print(f"更新cookies文件失败: {str(e)}")
        
        # 检查是否有数据被删除
        return len(new_data_list) < original_length
    
    except Exception as e:
        print(f"删除匹配的cf_clearance数据失败: {str(e)}")
        return False
