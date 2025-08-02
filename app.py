import os
import json
import uuid
import time
import base64
import sys
import inspect
import secrets
from loguru import logger
from pathlib import Path
import cf_util
import pickle
import threading

import requests
from flask import Flask, request, Response, jsonify, stream_with_context, render_template, redirect, session
from curl_cffi import requests as curl_requests
from werkzeug.middleware.proxy_fix import ProxyFix

from fastapi import FastAPI, HTTPException, Depends, Query, Body
from typing import List, Optional, Dict, Any
from faker import Faker
from pydantic import BaseModel


class Logger:
    def __init__(self, level="INFO", colorize=True, format=None):
        logger.remove()

        if format is None:
            format = (
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{extra[filename]}</cyan>:<cyan>{extra[function]}</cyan>:<cyan>{extra[lineno]}</cyan> | "
                "<level>{message}</level>"
            )

        logger.add(
            sys.stderr,
            level=level,
            format=format,
            colorize=colorize,
            backtrace=True,
            diagnose=True
        )

        self.logger = logger

    def _get_caller_info(self):
        frame = inspect.currentframe()
        try:
            caller_frame = frame.f_back.f_back
            full_path = caller_frame.f_code.co_filename
            function = caller_frame.f_code.co_name
            lineno = caller_frame.f_lineno

            filename = os.path.basename(full_path)

            return {
                'filename': filename,
                'function': function,
                'lineno': lineno
            }
        finally:
            del frame

    def info(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"[{source}] {message}")

    def error(self, message, source="API"):
        caller_info = self._get_caller_info()

        if isinstance(message, Exception):
            self.logger.bind(**caller_info).exception(f"[{source}] {str(message)}")
        else:
            self.logger.bind(**caller_info).error(f"[{source}] {message}")

    def warning(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).warning(f"[{source}] {message}")

    def debug(self, message, source="API"):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).debug(f"[{source}] {message}")

    async def request_logger(self, request):
        caller_info = self._get_caller_info()
        self.logger.bind(**caller_info).info(f"请求: {request.method} {request.path}", "Request")

# 禁用标准 logging 模块以避免与 loguru 冲突
import logging
logging.disable(logging.CRITICAL)

logger = Logger(level="INFO")
DATA_DIR = Path("./data")

if not DATA_DIR.exists():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG = {
    "MODELS": {
        "grok-3": "grok-3",
        "grok-3-search": "grok-3",
        "grok-3-imageGen": "grok-3",
        "grok-3-deepsearch": "grok-3",
        "grok-3-deepersearch": "grok-3",
        "grok-3-reasoning": "grok-3",
        'grok-4': 'grok-4',
        'grok-4-reasoning': 'grok-4',
        'grok-4-imageGen': 'grok-4',
        'grok-4-deepsearch': 'grok-4'
    },
    "API": {
        "IS_TEMP_CONVERSATION": os.environ.get("IS_TEMP_CONVERSATION", "true").lower() == "true",
        "IS_CUSTOM_SSO": os.environ.get("IS_CUSTOM_SSO", "false").lower() == "true",
        "BASE_URL": "https://grok.com",
        "API_KEY": os.environ.get("API_KEY", "sk-123456"),
        "SIGNATURE_COOKIE": None,
        "PICGO_KEY": os.environ.get("PICGO_KEY") or None,
        "TUMY_KEY": os.environ.get("TUMY_KEY") or None,
        "RETRY_TIME": 1000,
        "PROXY": os.environ.get("PROXY") or None
    },
    "ADMIN": {
        "MANAGER_SWITCH": os.environ.get("MANAGER_SWITCH") or None,
        "PASSWORD": os.environ.get("ADMINPASSWORD") or None
    },
    "SERVER": {
        "COOKIE": None,
        "CF_CLEARANCE":os.environ.get("CF_CLEARANCE") or None,
        "PORT": int(os.environ.get("PORT", 5200))
    },
    "RETRY": {
        "RETRYSWITCH": False,
        "MAX_ATTEMPTS": 2
    },
    "TOKEN_STATUS_FILE": str(DATA_DIR / "token_status.json"),
    "SHOW_THINKING": os.environ.get("SHOW_THINKING", "false").lower() == "true",
    "IS_THINKING": False,
    "IS_IMG_GEN": False,
    "IS_IMG_GEN2": False,
    "ISSHOW_SEARCH_RESULTS": os.environ.get("ISSHOW_SEARCH_RESULTS", "true").lower() == "true",
    "IS_SUPER_GROK": os.environ.get("IS_SUPER_GROK", "false").lower() == "true"
}


DEFAULT_HEADERS = {
    'Accept': '*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Content-Type': 'text/plain;charset=UTF-8',
    'Connection': 'keep-alive',
    'Origin': 'https://grok.com',
    'Priority': 'u=1, i',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36',
    'Sec-Ch-Ua': '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
    'Sec-Ch-Ua-Mobile': '?0',
    'Sec-Ch-Ua-Platform': '"macOS"',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-origin',
    'Baggage': 'sentry-public_key=b311e0f2690c81f25e2c4cf6d4f7ce1c',
    'x-statsig-id': 'ZTpUeXBlRXJyb3I6IENhbm5vdCByZWFkIHByb3BlcnRpZXMgb2YgdW5kZWZpbmVkIChyZWFkaW5nICdjaGlsZE5vZGVzJyk='
}

class AuthTokenManager:
    def __init__(self):
        self.token_model_map = {}
        self.expired_tokens = set()
        self.token_status_map = {}
        self.token_usage_records = {}  # 新增：记录每次token使用
        self.model_super_config = {
                "grok-3": {
                    "RequestFrequency": 100,
                    "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
                },
                "grok-3-deepsearch": {
                    "RequestFrequency": 30,
                    "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
                },
                "grok-3-deepersearch": {
                    "RequestFrequency": 10,
                    "ExpirationTime": 3 * 60 * 60 * 1000  # 3小时
                },
                "grok-3-reasoning": {
                    "RequestFrequency": 30,
                    "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
                },
                "grok-4": {
                    "RequestFrequency": 20,
                    "ExpirationTime": 3 * 60 * 60 * 1000  # 3小时
                }
            }
        self.model_normal_config = {
                "grok-3": {
                    "RequestFrequency": 20,
                    "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
                },
                "grok-3-deepsearch": {
                    "RequestFrequency": 10,
                    "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
                },
                "grok-3-deepersearch": {
                    "RequestFrequency": 3,
                    "ExpirationTime": 24 * 60 * 60 * 1000  # 24小时
                },
                "grok-3-reasoning": {
                    "RequestFrequency": 10,
                    "ExpirationTime": 2 * 60 * 60 * 1000  # 2小时
                }
            }
        self.model_config = self.model_normal_config
        self.token_reset_switch = False
        self.token_reset_timer = None
        self.usage_records_file = str(DATA_DIR / "token_usage_records.json")
    def save_token_status(self):
        try:
            with open(CONFIG["TOKEN_STATUS_FILE"], 'w', encoding='utf-8') as f:
                json.dump(self.token_status_map, f, indent=2, ensure_ascii=False)
            logger.info("令牌状态已保存到配置文件", "TokenManager")
        except Exception as error:
            logger.error(f"保存令牌状态失败: {str(error)}", "TokenManager")

    def load_token_status(self):
        try:
            token_status_file = Path(CONFIG["TOKEN_STATUS_FILE"])
            if token_status_file.exists():
                with open(token_status_file, 'r', encoding='utf-8') as f:
                    self.token_status_map = json.load(f)
                logger.info("已从配置文件加载令牌状态", "TokenManager")
        except Exception as error:
            logger.error(f"加载令牌状态失败: {str(error)}", "TokenManager")

    def save_usage_records(self):
        """保存token使用记录"""
        try:
            with open(self.usage_records_file, 'w', encoding='utf-8') as f:
                json.dump(self.token_usage_records, f, indent=2, ensure_ascii=False)
            logger.info("token使用记录已保存", "TokenManager")
        except Exception as error:
            logger.error(f"保存token使用记录失败: {str(error)}", "TokenManager")

    def load_usage_records(self):
        """加载token使用记录"""
        try:
            usage_records_file = Path(self.usage_records_file)
            if usage_records_file.exists():
                with open(usage_records_file, 'r', encoding='utf-8') as f:
                    self.token_usage_records = json.load(f)
                logger.info("已从文件加载token使用记录", "TokenManager")
        except Exception as error:
            logger.error(f"加载token使用记录失败: {str(error)}", "TokenManager")

    def record_token_usage(self, model_id, token, success=True):
        """记录token使用情况"""
        try:
            current_time = int(time.time() * 1000)
            sso = token.split("sso=")[1].split(";")[0] if "sso=" in token else "unknown"
            
            # 初始化记录结构
            if sso not in self.token_usage_records:
                self.token_usage_records[sso] = {}
            if model_id not in self.token_usage_records[sso]:
                self.token_usage_records[sso][model_id] = {
                    "total_calls": 0,
                    "successful_calls": 0,
                    "failed_calls": 0,
                    "last_call_time": None,
                    "call_history": []
                }
            
            # 记录使用情况
            record = self.token_usage_records[sso][model_id]
            record["total_calls"] += 1
            record["last_call_time"] = current_time
            
            if success:
                record["successful_calls"] += 1
            else:
                record["failed_calls"] += 1
            
            # 保留最近100次调用记录
            record["call_history"].append({
                "timestamp": current_time,
                "success": success,
                "model": model_id
            })
            if len(record["call_history"]) > 100:
                record["call_history"] = record["call_history"][-100:]
            
            # 定期保存记录
            if record["total_calls"] % 10 == 0:  # 每10次调用保存一次
                self.save_usage_records()
                
            logger.info(f"记录token使用: {model_id}, sso: {sso[:8]}..., 成功: {success}", "TokenManager")
            
        except Exception as error:
            logger.error(f"记录token使用失败: {str(error)}", "TokenManager")

    def get_usage_statistics(self, sso=None, model_id=None):
        """获取使用统计信息"""
        try:
            if sso and model_id:
                return self.token_usage_records.get(sso, {}).get(model_id, {})
            elif sso:
                return self.token_usage_records.get(sso, {})
            else:
                return self.token_usage_records
        except Exception as error:
            logger.error(f"获取使用统计失败: {str(error)}", "TokenManager")
            return {}
    def add_token(self, tokens, isinitialization=False):
        tokenType = tokens.get("type")
        tokenSso = tokens.get("token")
        if tokenType == "normal":
            self.model_config = self.model_normal_config
        else:
            self.model_config = self.model_super_config
        sso = tokenSso.split("sso=")[1].split(";")[0]

        for model in self.model_config.keys():
            if model not in self.token_model_map:
                self.token_model_map[model] = []
            if sso not in self.token_status_map:
                self.token_status_map[sso] = {}

            existing_token_entry = next((entry for entry in self.token_model_map[model] if entry["token"] == tokenSso), None)

            if not existing_token_entry:
                self.token_model_map[model].append({
                    "token": tokenSso,
                    "MaxRequestCount": self.model_config[model]["RequestFrequency"],
                    "RequestCount": 0,
                    "AddedTime": int(time.time() * 1000),
                    "StartCallTime": None,
                    "type": tokenType
                })

                if model not in self.token_status_map[sso]:
                    self.token_status_map[sso][model] = {
                        "isValid": True,
                        "invalidatedTime": None,
                        "totalRequestCount": 0,
                        "isSuper":tokenType == "super"
                    }
        if not isinitialization:
            self.save_token_status()

    def set_token(self, tokens):
        tokenType = tokens.get("type")
        tokenSso = tokens.get("token")
        if tokenType == "normal":
            self.model_config = self.model_normal_config
        else:
            self.model_config = self.model_super_config

        models = list(self.model_config.keys())
        self.token_model_map = {model: [{
            "token": tokenSso,
            "MaxRequestCount": self.model_config[model]["RequestFrequency"],
            "RequestCount": 0,
            "AddedTime": int(time.time() * 1000),
            "StartCallTime": None,
            "type": tokenType
        }] for model in models}

        sso = tokenSso.split("sso=")[1].split(";")[0]
        self.token_status_map[sso] = {model: {
            "isValid": True,
            "invalidatedTime": None,
            "totalRequestCount": 0,
            "isSuper":tokenType == "super"
        } for model in models}

    def delete_token(self, token):
        try:
            sso = token.split("sso=")[1].split(";")[0]
            for model in self.token_model_map:
                self.token_model_map[model] = [entry for entry in self.token_model_map[model] if entry["token"] != token]

            if sso in self.token_status_map:
                del self.token_status_map[sso]

            self.save_token_status()

            logger.info(f"令牌已成功移除: {token}", "TokenManager")
            return True
        except Exception as error:
            logger.error(f"令牌删除失败: {str(error)}")
            return False
    def reduce_token_request_count(self, model_id, count):
        try:
            normalized_model = self.normalize_model_name(model_id)

            if normalized_model not in self.token_model_map:
                logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
                return False

            if not self.token_model_map[normalized_model]:
                logger.error(f"模型 {normalized_model} 没有可用的token", "TokenManager")
                return False

            token_entry = self.token_model_map[normalized_model][0]

            # 确保RequestCount不会小于0
            new_count = max(0, token_entry["RequestCount"] - count)
            reduction = token_entry["RequestCount"] - new_count

            token_entry["RequestCount"] = new_count

            # 更新token状态
            if token_entry["token"]:
                sso = token_entry["token"].split("sso=")[1].split(";")[0]
                if sso in self.token_status_map and normalized_model in self.token_status_map[sso]:
                    self.token_status_map[sso][normalized_model]["totalRequestCount"] = max(
                        0,
                        self.token_status_map[sso][normalized_model]["totalRequestCount"] - reduction
                    )
            return True

        except Exception as error:
            logger.error(f"重置校对token请求次数时发生错误: {str(error)}", "TokenManager")
            return False
    def get_next_token_for_model(self, model_id, is_return=False):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map or not self.token_model_map[normalized_model]:
            return None

        token_entry = self.token_model_map[normalized_model][0]
        logger.info(f"token_entry: {token_entry}", "TokenManager")
        if is_return:
            return token_entry["token"]

        if token_entry:
            if token_entry["type"] == "super":
                self.model_config = self.model_super_config
            else:
                self.model_config = self.model_normal_config
            if token_entry["StartCallTime"] is None:
                token_entry["StartCallTime"] = int(time.time() * 1000)

            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True

            token_entry["RequestCount"] += 1

            # 记录token使用
            self.record_token_usage(normalized_model, token_entry["token"], True)

            if token_entry["RequestCount"] > token_entry["MaxRequestCount"]:
                self.remove_token_from_model(normalized_model, token_entry["token"])
                next_token_entry = self.token_model_map[normalized_model][0] if self.token_model_map[normalized_model] else None
                return next_token_entry["token"] if next_token_entry else None

            sso = token_entry["token"].split("sso=")[1].split(";")[0]

            if sso in self.token_status_map and normalized_model in self.token_status_map[sso]:
                if token_entry["RequestCount"] == self.model_config[normalized_model]["RequestFrequency"]:
                    self.token_status_map[sso][normalized_model]["isValid"] = False
                    self.token_status_map[sso][normalized_model]["invalidatedTime"] = int(time.time() * 1000)
                
                # 确保与usage_records保持一致
                usage_record = self.token_usage_records.get(sso, {}).get(normalized_model, {})
                if usage_record:
                    self.token_status_map[sso][normalized_model]["totalRequestCount"] = usage_record.get("total_calls", 0)
                else:
                    self.token_status_map[sso][normalized_model]["totalRequestCount"] += 1

                self.save_token_status()

            return token_entry["token"]

        return None

    def remove_token_from_model(self, model_id, token):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map:
            logger.error(f"模型 {normalized_model} 不存在", "TokenManager")
            return False

        model_tokens = self.token_model_map[normalized_model]
        token_index = next((i for i, entry in enumerate(model_tokens) if entry["token"] == token), -1)

        if token_index != -1:
            removed_token_entry = model_tokens.pop(token_index)
            self.expired_tokens.add((
                removed_token_entry["token"],
                normalized_model,
                int(time.time() * 1000),
                removed_token_entry["type"]
            ))

            if not self.token_reset_switch:
                self.start_token_reset_process()
                self.token_reset_switch = True

            logger.info(f"模型{model_id}的令牌已失效，已成功移除令牌: {token}", "TokenManager")
            return True

        logger.error(f"在模型 {normalized_model} 中未找到 token: {token}", "TokenManager")
        return False

    def get_expired_tokens(self):
        return list(self.expired_tokens)

    def normalize_model_name(self, model):
        if model.startswith('grok-') and not any(keyword in model for keyword in ['deepsearch','deepersearch','reasoning']):
            return '-'.join(model.split('-')[:2])
        return model

    def get_token_count_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return len(self.token_model_map.get(normalized_model, []))

    def get_remaining_token_request_capacity(self):
        remaining_capacity_map = {}

        for model in self.model_config.keys():
            model_tokens = self.token_model_map.get(model, [])

            model_request_frequency = sum(token_entry.get("MaxRequestCount", 0) for token_entry in model_tokens)
            total_used_requests = sum(token_entry.get("RequestCount", 0) for token_entry in model_tokens)

            remaining_capacity = (len(model_tokens) * model_request_frequency) - total_used_requests
            remaining_capacity_map[model] = max(0, remaining_capacity)

        return remaining_capacity_map

    def get_token_array_for_model(self, model_id):
        normalized_model = self.normalize_model_name(model_id)
        return self.token_model_map.get(normalized_model, [])

    def start_token_reset_process(self):
        def reset_expired_tokens():
            now = int(time.time() * 1000)

            model_config = self.model_normal_config
            tokens_to_remove = set()
            for token_info in self.expired_tokens:
                token, model, expired_time ,type = token_info
                if type == "super":
                    model_config = self.model_super_config
                expiration_time = model_config[model]["ExpirationTime"]

                if now - expired_time >= expiration_time:
                    if not any(entry["token"] == token for entry in self.token_model_map.get(model, [])):
                        if model not in self.token_model_map:
                            self.token_model_map[model] = []

                        self.token_model_map[model].append({
                            "token": token,
                            "MaxRequestCount": model_config[model]["RequestFrequency"],
                            "RequestCount": 0,
                            "AddedTime": now,
                            "StartCallTime": None,
                            "type": type
                        })

                    sso = token.split("sso=")[1].split(";")[0]
                    if sso in self.token_status_map and model in self.token_status_map[sso]:
                        self.token_status_map[sso][model]["isValid"] = True
                        self.token_status_map[sso][model]["invalidatedTime"] = None
                        self.token_status_map[sso][model]["totalRequestCount"] = 0
                        self.token_status_map[sso][model]["isSuper"] = type == "super"

                    # 记录token重置
                    logger.info(f"Token重置: {model}, sso: {sso[:8]}..., 类型: {type}", "TokenManager")
                    tokens_to_remove.add(token_info)

            self.expired_tokens -= tokens_to_remove

            for model in model_config.keys():
                if model not in self.token_model_map:
                    continue

                for token_entry in self.token_model_map[model]:
                    if not token_entry.get("StartCallTime"):
                        continue

                    expiration_time = model_config[model]["ExpirationTime"]
                    if now - token_entry["StartCallTime"] >= expiration_time:
                        sso = token_entry["token"].split("sso=")[1].split(";")[0]
                        if sso in self.token_status_map and model in self.token_status_map[sso]:
                            self.token_status_map[sso][model]["isValid"] = True
                            self.token_status_map[sso][model]["invalidatedTime"] = None
                            self.token_status_map[sso][model]["totalRequestCount"] = 0
                            self.token_status_map[sso][model]["isSuper"] = token_entry["type"] == "super"

                        token_entry["RequestCount"] = 0
                        token_entry["StartCallTime"] = None
                        
                        # 记录token重置
                        logger.info(f"Token定时重置: {model}, sso: {sso[:8]}..., 类型: {token_entry['type']}", "TokenManager")

        import threading
        # 启动一个线程执行定时任务，每30分钟执行一次（更频繁检查2小时重置）
        def run_timer():
            while True:
                reset_expired_tokens()
                time.sleep(1800)  # 30分钟检查一次

        timer_thread = threading.Thread(target=run_timer)
        timer_thread.daemon = True
        timer_thread.start()

    def get_all_tokens(self):
        all_tokens = set()
        for model_tokens in self.token_model_map.values():
            for entry in model_tokens:
                all_tokens.add(entry["token"])
        return list(all_tokens)
    def get_current_token(self, model_id):
        normalized_model = self.normalize_model_name(model_id)

        if normalized_model not in self.token_model_map or not self.token_model_map[normalized_model]:
            return None

        token_entry = self.token_model_map[normalized_model][0]
        return token_entry["token"]

    def get_token_status_map(self):
        return self.token_status_map

    def check_and_reset_expired_tokens(self):
        """检查并重置过期的token状态"""
        try:
            now = int(time.time() * 1000)
            
            # 检查expired_tokens中的token是否可以重置
            tokens_to_remove = set()
            for token_info in self.expired_tokens:
                token, model, expired_time, type = token_info
                model_config = self.model_super_config if type == "super" else self.model_normal_config
                expiration_time = model_config[model]["ExpirationTime"]

                if now - expired_time >= expiration_time:
                    # 重新激活token
                    if not any(entry["token"] == token for entry in self.token_model_map.get(model, [])):
                        if model not in self.token_model_map:
                            self.token_model_map[model] = []

                        self.token_model_map[model].append({
                            "token": token,
                            "MaxRequestCount": model_config[model]["RequestFrequency"],
                            "RequestCount": 0,
                            "AddedTime": now,
                            "StartCallTime": None,
                            "type": type
                        })

                    sso = token.split("sso=")[1].split(";")[0] if "sso=" in token else "unknown"
                    if sso in self.token_status_map and model in self.token_status_map[sso]:
                        self.token_status_map[sso][model]["isValid"] = True
                        self.token_status_map[sso][model]["invalidatedTime"] = None
                        self.token_status_map[sso][model]["totalRequestCount"] = 0
                        self.token_status_map[sso][model]["isSuper"] = type == "super"

                    logger.info(f"Token已重置: {model}, sso: {sso[:8]}..., 类型: {type}", "TokenManager")
                    tokens_to_remove.add(token_info)

            self.expired_tokens -= tokens_to_remove

            # 检查当前活跃token是否需要重置
            for model in list(self.token_model_map.keys()):
                if model not in self.token_model_map:
                    continue

                for token_entry in self.token_model_map[model]:
                    if not token_entry.get("StartCallTime"):
                        continue

                    model_config = self.model_super_config if token_entry["type"] == "super" else self.model_normal_config
                    expiration_time = model_config[model]["ExpirationTime"]
                    
                    if now - token_entry["StartCallTime"] >= expiration_time:
                        sso = token_entry["token"].split("sso=")[1].split(";")[0] if "sso=" in token_entry["token"] else "unknown"
                        
                        if sso in self.token_status_map and model in self.token_status_map[sso]:
                            self.token_status_map[sso][model]["isValid"] = True
                            self.token_status_map[sso][model]["invalidatedTime"] = None
                            self.token_status_map[sso][model]["totalRequestCount"] = 0
                            self.token_status_map[sso][model]["isSuper"] = token_entry["type"] == "super"

                        token_entry["RequestCount"] = 0
                        token_entry["StartCallTime"] = None
                        
                        logger.info(f"Token实时重置: {model}, sso: {sso[:8]}..., 类型: {token_entry['type']}", "TokenManager")

            # 保存更新后的状态
            self.save_token_status()
            
        except Exception as error:
            logger.error(f"检查和重置过期token时发生错误: {str(error)}", "TokenManager")

class Utils:
    @staticmethod
    def organize_search_results(search_results):
        if not search_results or 'results' not in search_results:
            return ''

        results = search_results['results']
        formatted_results = []

        for index, result in enumerate(results):
            title = result.get('title', '未知标题')
            url = result.get('url', '#')
            preview = result.get('preview', '无预览内容')

            formatted_result = f"\r\n<details><summary>资料[{index}]: {title}</summary>\r\n{preview}\r\n\n[Link]({url})\r\n</details>"
            formatted_results.append(formatted_result)

        return '\n\n'.join(formatted_results)

    @staticmethod
    def create_auth_headers(model, is_return=False):
        return token_manager.get_next_token_for_model(model, is_return)

    @staticmethod
    def get_proxy_options():
        proxy = CONFIG["API"]["PROXY"]
        proxy_options = {}

        if proxy:
            logger.info(f"使用代理: {proxy}", "Server")

            if proxy.startswith("socks5://"):
                proxy_options["proxy"] = proxy

                if '@' in proxy:
                    auth_part = proxy.split('@')[0].split('://')[1]
                    if ':' in auth_part:
                        username, password = auth_part.split(':')
                        proxy_options["proxy_auth"] = (username, password)
            else:
                proxy_options["proxies"] = {"https": proxy, "http": proxy}
        return proxy_options

class GrokApiClient:
    def __init__(self, model_id):
        if model_id not in CONFIG["MODELS"]:
            raise ValueError(f"不支持的模型: {model_id}")
        self.model_id = CONFIG["MODELS"][model_id]

    def process_message_content(self, content):
        if isinstance(content, str):
            return content
        return None

    def get_image_type(self, base64_string):
        mime_type = 'image/jpeg'
        if 'data:image' in base64_string:
            import re
            matches = re.search(r'data:([a-zA-Z0-9]+\/[a-zA-Z0-9-.+]+);base64,', base64_string)
            if matches:
                mime_type = matches.group(1)

        extension = mime_type.split('/')[1]
        file_name = f"image.{extension}"

        return {
            "mimeType": mime_type,
            "fileName": file_name
        }
    def upload_base64_file(self, message, model):
        try:
            message_base64 = base64.b64encode(message.encode('utf-8')).decode('utf-8')
            upload_data = {
                "fileName": "message.txt",
                "fileMimeType": "text/plain",
                "content": message_base64
            }

            logger.info("发送文字文件请求", "Server")
            # 获取cf_clearance值，如果已配置的为空则从文件获取
            cf_clearance_values = cf_util.get_cf_clearance_value()
            if not CONFIG['SERVER']['CF_CLEARANCE'] and cf_clearance_values:
                CONFIG['SERVER']['CF_CLEARANCE'] = cf_clearance_values[0]  # 使用第一个找到的值
            cookie = f"{Utils.create_auth_headers(model, True)};{CONFIG['SERVER']['CF_CLEARANCE']}"
            proxy_options = Utils.get_proxy_options()
            response = curl_requests.post(
                "https://grok.com/rest/app-chat/upload-file",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie":cookie
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options
            )

            if response.status_code != 200:
                logger.error(f"上传文件失败,状态码:{response.status_code}", "Server")
                raise Exception(f"上传文件失败,状态码:{response.status_code}")

            result = response.json()
            logger.info(f"上传文件成功: {result}", "Server")
            return result.get("fileMetadataId", "")

        except Exception as error:
            logger.error(str(error), "Server")
            raise Exception(f"上传文件失败,状态码:{response.status_code}")
    def upload_base64_image(self, base64_data, url):
        try:
            if 'data:image' in base64_data:
                image_buffer = base64_data.split(',')[1]
            else:
                image_buffer = base64_data

            image_info = self.get_image_type(base64_data)
            mime_type = image_info["mimeType"]
            file_name = image_info["fileName"]

            upload_data = {
                "rpc": "uploadFile",
                "req": {
                    "fileName": file_name,
                    "fileMimeType": mime_type,
                    "content": image_buffer
                }
            }

            logger.info("发送图片请求", "Server")

            proxy_options = Utils.get_proxy_options()
            response = curl_requests.post(
                url,
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie":CONFIG["SERVER"]['COOKIE']
                },
                json=upload_data,
                impersonate="chrome133a",
                **proxy_options
            )

            if response.status_code != 200:
                logger.error(f"上传图片失败,状态码:{response.status_code}", "Server")
                return ''

            result = response.json()
            logger.info(f"上传图片成功: {result}", "Server")
            return result.get("fileMetadataId", "")

        except Exception as error:
            logger.error(str(error), "Server")
            return ''
    # def convert_system_messages(self, messages):
    #     try:
    #         system_prompt = []
    #         i = 0
    #         while i < len(messages):
    #             if messages[i].get('role') != 'system':
    #                 break

    #             system_prompt.append(self.process_message_content(messages[i].get('content')))
    #             i += 1

    #         messages = messages[i:]
    #         system_prompt = '\n'.join(system_prompt)

    #         if not messages:
    #             raise ValueError("没有找到用户或者AI消息")
    #         return {"system_prompt":system_prompt,"messages":messages}
    #     except Exception as error:
    #         logger.error(str(error), "Server")
    #         raise ValueError(error)
    def prepare_chat_request(self, request):
        if ((request["model"] == 'grok-4-imageGen' or request["model"] == 'grok-3-imageGen') and
            not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"] and
            request.get("stream", False)):
            raise ValueError("该模型流式输出需要配置PICGO或者TUMY图床密钥!")

        # system_message, todo_messages = self.convert_system_messages(request["messages"]).values()
        todo_messages = request["messages"]
        if request["model"] in ['grok-4-imageGen', 'grok-3-imageGen', 'grok-3-deepsearch']:
            last_message = todo_messages[-1]
            if last_message["role"] != 'user':
                raise ValueError('此模型最后一条消息必须是用户消息!')
            todo_messages = [last_message]
        file_attachments = []
        messages = ''
        last_role = None
        last_content = ''
        message_length = 0
        convert_to_file = False
        last_message_content = ''
        search = request["model"] in ['grok-4-deepsearch', 'grok-3-search']
        deepsearchPreset = ''
        if request["model"] == 'grok-3-deepsearch':
            deepsearchPreset = 'default'
        elif request["model"] == 'grok-3-deepersearch':
            deepsearchPreset = 'deeper'

        # 移除<think>标签及其内容和base64图片
        def remove_think_tags(text):
            import re
            text = re.sub(r'<think>[\s\S]*?<\/think>', '', text).strip()
            text = re.sub(r'!\[image\]\(data:.*?base64,.*?\)', '[图片]', text)
            return text

        def process_content(content):
            if isinstance(content, list):
                text_content = ''
                for item in content:
                    if item["type"] == 'image_url':
                        text_content += ("[图片]" if not text_content else '\n[图片]')
                    elif item["type"] == 'text':
                        text_content += (remove_think_tags(item["text"]) if not text_content else '\n' + remove_think_tags(item["text"]))
                return text_content
            elif isinstance(content, dict) and content is not None:
                if content["type"] == 'image_url':
                    return "[图片]"
                elif content["type"] == 'text':
                    return remove_think_tags(content["text"])
            return remove_think_tags(self.process_message_content(content))
        for current in todo_messages:
            role = 'assistant' if current["role"] == 'assistant' else 'user'
            is_last_message = current == todo_messages[-1]

            if is_last_message and "content" in current:
                if isinstance(current["content"], list):
                    for item in current["content"]:
                        if item["type"] == 'image_url':
                            processed_image = self.upload_base64_image(
                                item["image_url"]["url"],
                                f"{CONFIG['API']['BASE_URL']}/api/rpc"
                            )
                            if processed_image:
                                file_attachments.append(processed_image)
                elif isinstance(current["content"], dict) and current["content"].get("type") == 'image_url':
                    processed_image = self.upload_base64_image(
                        current["content"]["image_url"]["url"],
                        f"{CONFIG['API']['BASE_URL']}/api/rpc"
                    )
                    if processed_image:
                        file_attachments.append(processed_image)


            text_content = process_content(current.get("content", ""))
            if is_last_message and convert_to_file:
                last_message_content = f"{role.upper()}: {text_content or '[图片]'}\n"
                continue
            if text_content or (is_last_message and file_attachments):
                if role == last_role and text_content:
                    last_content += '\n' + text_content
                    messages = messages[:messages.rindex(f"{role.upper()}: ")] + f"{role.upper()}: {last_content}\n"
                else:
                    messages += f"{role.upper()}: {text_content or '[图片]'}\n"
                    last_content = text_content
                    last_role = role
            message_length += len(messages)
            if message_length >= 40000:
                convert_to_file = True

        if convert_to_file:
            file_id = self.upload_base64_file(messages, request["model"])
            if file_id:
                file_attachments.insert(0, file_id)
            messages = last_message_content.strip()
        if messages.strip() == '':
            if convert_to_file:
                messages = '基于txt文件内容进行回复：'
            else:
                raise ValueError('消息内容为空!')
        return {
            "temporary": CONFIG["API"].get("IS_TEMP_CONVERSATION", False),
            "modelName": self.model_id,
            "message": messages.strip(),
            "fileAttachments": file_attachments[:4],
            "imageAttachments": [],
            "disableSearch": False,
            "enableImageGeneration": True,
            "returnImageBytes": False,
            "returnRawGrokInXaiRequest": False,
            "enableImageStreaming": False,
            "imageGenerationCount": 1,
            "forceConcise": False,
            "toolOverrides": {
                "imageGen": request["model"] in ['grok-4-imageGen', 'grok-3-imageGen'],
                "webSearch": search,
                "xSearch": search,
                "xMediaSearch": search,
                "trendsSearch": search,
                "xPostAnalyze": search
            },
            "enableSideBySide": True,
            "sendFinalMetadata": True,
            "customPersonality": "",
            "deepsearchPreset": deepsearchPreset,
            "isReasoning": request["model"] == 'grok-3-reasoning',
            "disableTextFollowUps": True
        }

class MessageProcessor:
    @staticmethod
    def create_chat_response(message, model, is_stream=False):
        base_response = {
            "id": f"chatcmpl-{uuid.uuid4()}",
            "created": int(time.time()),
            "model": model
        }

        if is_stream:
            return {
                **base_response,
                "object": "chat.completion.chunk",
                "choices": [{
                    "index": 0,
                    "delta": {
                        "content": message
                    }
                }]
            }

        return {
            **base_response,
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": message
                },
                "finish_reason": "stop"
            }],
            "usage": None
        }

def process_model_response(response, model):
    result = {"token": None, "imageUrl": None}

    if CONFIG["IS_IMG_GEN"]:
        if response.get("cachedImageGenerationResponse") and not CONFIG["IS_IMG_GEN2"]:
            result["imageUrl"] = response["cachedImageGenerationResponse"]["imageUrl"]
        return result
    if model == 'grok-3':
        result["token"] = response.get("token")
    elif model in ['grok-3-search']:
        if response.get("webSearchResults") and CONFIG["ISSHOW_SEARCH_RESULTS"]:
            result["token"] = f"\r\n<think>{Utils.organize_search_results(response['webSearchResults'])}</think>\r\n"
        else:
            result["token"] = response.get("token")
    elif model in ['grok-3-deepsearch', 'grok-3-deepersearch','grok-4-deepsearch']:
        if response.get("messageStepId") and not CONFIG["SHOW_THINKING"]:
            return result
        if response.get("messageStepId") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "final":
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        elif (response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "assistant") or response.get("messageTag") == "final":
            result["token"] = response.get("token","")
        elif (CONFIG["IS_THINKING"] and response.get("token","").get("action","") == "webSearch"):
            result["token"] = response.get("token","").get("action_input","").get("query","")
        elif (CONFIG["IS_THINKING"] and response.get("webSearchResults")):
            result["token"] = Utils.organize_search_results(response['webSearchResults'])
    elif model == 'grok-3-reasoning':
        if response.get("isThinking") and not CONFIG["SHOW_THINKING"]:
            return result

        if response.get("isThinking") and not CONFIG["IS_THINKING"]:
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("isThinking") and CONFIG["IS_THINKING"]:
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        else:
            result["token"] = response.get("token")

    elif model == 'grok-4':
        if response.get("isThinking"):
            return result
        result["token"] = response.get("token")
    elif model == 'grok-4-reasoning':
        if response.get("isThinking") and not CONFIG["SHOW_THINKING"]:
            return result
        if response.get("isThinking") and not CONFIG["IS_THINKING"] and response.get("messageTag") == "assistant":
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("isThinking") and CONFIG["IS_THINKING"] and response.get("messageTag") == "final":
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        else:
            result["token"] = response.get("token")
    elif model in ['grok-4-deepsearch']:
        if response.get("messageStepId") and not CONFIG["SHOW_THINKING"]:
            return result
        if response.get("messageStepId") and not CONFIG["IS_THINKING"] and response.get("messageTag") == "assistant":
            result["token"] = "<think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = True
        elif not response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "final":
            result["token"] = "</think>" + response.get("token", "")
            CONFIG["IS_THINKING"] = False
        elif (response.get("messageStepId") and CONFIG["IS_THINKING"] and response.get("messageTag") == "assistant") or response.get("messageTag") == "final":
            result["token"] = response.get("token","")
        elif (CONFIG["IS_THINKING"] and response.get("token","").get("action","") == "webSearch"):
            result["token"] = response.get("token","").get("action_input","").get("query","")
        elif (CONFIG["IS_THINKING"] and response.get("webSearchResults")):
            result["token"] = Utils.organize_search_results(response['webSearchResults'])

    return result

def handle_image_response(image_url):
    max_retries = 2
    retry_count = 0
    image_base64_response = None

    while retry_count < max_retries:
        try:
            proxy_options = Utils.get_proxy_options()
            image_base64_response = curl_requests.get(
                f"https://assets.grok.com/{image_url}",
                headers={
                    **DEFAULT_HEADERS,
                    "Cookie":CONFIG["SERVER"]['COOKIE']
                },
                impersonate="chrome133a",
                **proxy_options
            )

            if image_base64_response.status_code == 200:
                break

            retry_count += 1
            if retry_count == max_retries:
                raise Exception(f"上游服务请求失败! status: {image_base64_response.status_code}")

            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

        except Exception as error:
            logger.error(str(error), "Server")
            retry_count += 1
            if retry_count == max_retries:
                raise

            time.sleep(CONFIG["API"]["RETRY_TIME"] / 1000 * retry_count)

    image_buffer = image_base64_response.content

    if not CONFIG["API"]["PICGO_KEY"] and not CONFIG["API"]["TUMY_KEY"]:
        base64_image = base64.b64encode(image_buffer).decode('utf-8')
        image_content_type = image_base64_response.headers.get('content-type', 'image/jpeg')
        return f"![image](data:{image_content_type};base64,{base64_image})"

    logger.info("开始上传图床", "Server")

    if CONFIG["API"]["PICGO_KEY"]:
        files = {'source': ('image.jpg', image_buffer, 'image/jpeg')}
        headers = {
            "X-API-Key": CONFIG["API"]["PICGO_KEY"]
        }

        response_url = requests.post(
            "https://www.picgo.net/api/1/upload",
            files=files,
            headers=headers
        )

        if response_url.status_code != 200:
            return "生图失败，请查看PICGO图床密钥是否设置正确"
        else:
            logger.info("生图成功", "Server")
            result = response_url.json()
            return f"![image]({result['image']['url']})"


    elif CONFIG["API"]["TUMY_KEY"]:
        files = {'file': ('image.jpg', image_buffer, 'image/jpeg')}
        headers = {
            "Accept": "application/json",
            'Authorization': f"Bearer {CONFIG['API']['TUMY_KEY']}"
        }

        response_url = requests.post(
            "https://tu.my/api/v1/upload",
            files=files,
            headers=headers
        )

        if response_url.status_code != 200:
            return "生图失败，请查看TUMY图床密钥是否设置正确"
        else:
            try:
                result = response_url.json()
                logger.info("生图成功", "Server")
                return f"![image]({result['data']['links']['url']})"
            except Exception as error:
                logger.error(str(error), "Server")
                return "生图失败，请查看TUMY图床密钥是否设置正确"

def handle_non_stream_response(response, model):
    try:
        logger.info("开始处理非流式响应", "Server")

        stream = response.iter_lines()
        full_response = ""
        
        CONFIG["IS_THINKING"] = False
        CONFIG["IS_IMG_GEN"] = False
        CONFIG["IS_IMG_GEN2"] = False
        
        chunk_count = 0
        error_count = 0

        for chunk in stream:
            if not chunk:
                continue
                
            chunk_count += 1
            logger.debug(f"处理非流式响应第 {chunk_count} 个数据块", "Server")
            
            try:
                chunk_str = chunk.decode("utf-8").strip()
                if not chunk_str:
                    continue
                    
                line_json = json.loads(chunk_str)
                logger.debug(f"非流式响应JSON解析成功: {json.dumps(line_json, ensure_ascii=False)}", "Server")
                
                # 检查是否有错误
                if line_json.get("error"):
                    error_info = line_json.get("error")
                    error_code = error_info.get("code", "unknown")
                    error_message = error_info.get("message", "Unknown error")
                    
                    logger.error(f"非流式响应中收到错误 - 代码: {error_code}, 消息: {error_message}, 详细信息: {json.dumps(line_json, indent=2, ensure_ascii=False)}", "Server")
                    
                    # 根据错误类型决定如何处理
                    if error_code == 13:  # "Failed to respond" 错误
                        logger.warning("非流式响应检测到 'Failed to respond' 错误", "Server")
                        if full_response:
                            logger.info(f"返回已收集的部分响应内容，长度: {len(full_response)}", "Server")
                            return full_response
                        else:
                            return "[响应被中断，请重试]"
                    else:
                        # 其他错误类型，返回错误信息
                        return f"[错误: {error_message}]"

                response_data = line_json.get("result", {}).get("response")
                if not response_data:
                    logger.debug("非流式响应数据为空，跳过此块", "Server")
                    continue

                if response_data.get("doImgGen") or response_data.get("imageAttachmentInfo"):
                    CONFIG["IS_IMG_GEN"] = True
                    logger.debug("非流式响应检测到图片生成请求", "Server")

                result = process_model_response(response_data, model)

                if result and result.get("token"):
                    token_content = result["token"]
                    if token_content:  # 确保token不为空
                        full_response += token_content

                if result and result.get("imageUrl"):
                    CONFIG["IS_IMG_GEN2"] = True
                    logger.info("非流式响应开始处理图片", "Server")
                    try:
                        return handle_image_response(result["imageUrl"])
                    except Exception as img_error:
                        logger.error(f"非流式响应处理图片时出错: {str(img_error)}", "Server")
                        return "[图片处理失败]"

            except json.JSONDecodeError as json_error:
                error_count += 1
                logger.warning(f"非流式响应JSON解析失败 (第{error_count}次): {str(json_error)}, 原始数据: {chunk_str[:200]}...", "Server")
                if error_count > 10:  # 如果连续解析失败太多次，返回已有内容
                    logger.error("非流式响应JSON解析失败次数过多，返回已收集内容", "Server")
                    return full_response if full_response else "[数据解析错误]"
                continue
                
            except Exception as chunk_error:
                error_count += 1
                logger.error(f"非流式响应处理数据块时出错 (第{error_count}次): {str(chunk_error)}", "Server")
                if error_count > 5:  # 如果错误太多，返回已有内容
                    logger.error("非流式响应处理错误次数过多，返回已收集内容", "Server")
                    return full_response if full_response else "[处理错误过多]"
                continue

        logger.info(f"非流式响应处理完成，共处理 {chunk_count} 个数据块，错误 {error_count} 次，响应长度: {len(full_response)}", "Server")
        return full_response if full_response else "[未收到有效响应]"
        
    except Exception as error:
        logger.error(f"非流式响应处理发生严重错误: {str(error)}", "Server")
        raise Exception(f"非流式响应处理失败: {str(error)}")
def handle_stream_response(response, model):
    def generate():
        logger.info("开始处理流式响应", "Server")
        
        try:
            stream = response.iter_lines()
            CONFIG["IS_THINKING"] = False
            CONFIG["IS_IMG_GEN"] = False
            CONFIG["IS_IMG_GEN2"] = False
            
            chunk_count = 0
            error_count = 0
            
            for chunk in stream:
                if not chunk:
                    continue
                    
                chunk_count += 1
                logger.debug(f"处理第 {chunk_count} 个数据块", "Server")
                
                try:
                    chunk_str = chunk.decode("utf-8").strip()
                    if not chunk_str:
                        continue
                        
                    line_json = json.loads(chunk_str)
                    logger.debug(f"解析JSON成功: {json.dumps(line_json, ensure_ascii=False)}", "Server")
                    
                    # 检查是否有错误
                    if line_json.get("error"):
                        error_info = line_json.get("error")
                        error_code = error_info.get("code", "unknown")
                        error_message = error_info.get("message", "Unknown error")
                        
                        logger.error(f"流式响应中收到错误 - 代码: {error_code}, 消息: {error_message}, 详细信息: {json.dumps(line_json, indent=2, ensure_ascii=False)}", "Server")
                        
                        # 根据错误类型决定如何处理
                        if error_code == 13:  # "Failed to respond" 错误
                            logger.warning("检测到 'Failed to respond' 错误，尝试优雅结束流式响应", "Server")
                            yield f"data: {json.dumps(MessageProcessor.create_chat_response('[响应被中断，请重试]', model, True))}\n\n"
                            yield "data: [DONE]\n\n"
                            return
                        else:
                            # 其他错误类型
                            error_response = {
                                "error": {
                                    "message": f"流式响应错误: {error_message}",
                                    "type": "stream_error",
                                    "code": error_code
                                }
                            }
                            yield f"data: {json.dumps(error_response)}\n\n"
                            yield "data: [DONE]\n\n"
                            return

                    # 处理正常响应数据
                    response_data = line_json.get("result", {}).get("response")
                    if not response_data:
                        logger.debug("响应数据为空，跳过此块", "Server")
                        continue

                    if response_data.get("doImgGen") or response_data.get("imageAttachmentInfo"):
                        CONFIG["IS_IMG_GEN"] = True
                        logger.debug("检测到图片生成请求", "Server")

                    result = process_model_response(response_data, model)

                    if result and result.get("token"):
                        token_content = result["token"]
                        if token_content:  # 确保token不为空
                            yield f"data: {json.dumps(MessageProcessor.create_chat_response(token_content, model, True))}\n\n"

                    if result and result.get("imageUrl"):
                        CONFIG["IS_IMG_GEN2"] = True
                        logger.info("开始处理图片响应", "Server")
                        try:
                            image_data = handle_image_response(result["imageUrl"])
                            yield f"data: {json.dumps(MessageProcessor.create_chat_response(image_data, model, True))}\n\n"
                        except Exception as img_error:
                            logger.error(f"处理图片响应时出错: {str(img_error)}", "Server")
                            yield f"data: {json.dumps(MessageProcessor.create_chat_response('[图片处理失败]', model, True))}\n\n"

                except json.JSONDecodeError as json_error:
                    error_count += 1
                    logger.warning(f"JSON解析失败 (第{error_count}次): {str(json_error)}, 原始数据: {chunk_str[:200]}...", "Server")
                    if error_count > 10:  # 如果连续解析失败太多次，终止流
                        logger.error("JSON解析失败次数过多，终止流式响应", "Server")
                        yield f"data: {json.dumps(MessageProcessor.create_chat_response('[数据解析错误，响应终止]', model, True))}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                    continue
                    
                except Exception as chunk_error:
                    error_count += 1
                    logger.error(f"处理数据块时出错 (第{error_count}次): {str(chunk_error)}", "Server")
                    if error_count > 5:  # 如果错误太多，终止流
                        logger.error("处理错误次数过多，终止流式响应", "Server")
                        yield f"data: {json.dumps(MessageProcessor.create_chat_response('[处理错误过多，响应终止]', model, True))}\n\n"
                        yield "data: [DONE]\n\n"
                        return
                    continue

            logger.info(f"流式响应处理完成，共处理 {chunk_count} 个数据块，错误 {error_count} 次", "Server")
            yield "data: [DONE]\n\n"
            
        except Exception as stream_error:
            logger.error(f"流式响应处理发生严重错误: {str(stream_error)}", "Server")
            try:
                yield f"data: {json.dumps(MessageProcessor.create_chat_response('[流式响应处理失败]', model, True))}\n\n"
                yield "data: [DONE]\n\n"
            except:
                pass  # 如果连yield都失败了，就静默处理
                
    return generate()

def save_token_manager(token_manager_obj, file_path="token_manager.pickle"):
    """
    将token_manager对象序列化保存到文件
    
    Args:
        token_manager_obj: token_manager对象
        file_path: 保存的文件路径
    """
    try:
        data_dir = Path("./data")
        if not data_dir.exists():
            data_dir.mkdir(parents=True, exist_ok=True)

        full_path = data_dir / file_path

        with open(full_path, 'wb') as f:
            pickle.dump(token_manager_obj, f)

        logger.info(f"成功保存token_manager对象到: {full_path}", "TokenPersistence")
    except Exception as error:
        logger.error(f"保存token_manager对象失败: {str(error)}", "TokenPersistence")

def load_token_manager(file_path="token_manager.pickle"):
    """
    从文件加载token_manager对象
    
    Args:
        file_path: token_manager对象的文件路径
        
    Returns:
        加载的token_manager对象，如果加载失败则返回None
    """
    try:
        data_dir = Path("./data")
        full_path = data_dir / file_path

        if not full_path.exists():
            logger.info(f"token_manager对象文件不存在: {full_path}", "TokenPersistence")
            return None

        with open(full_path, 'rb') as f:
            token_manager_obj = pickle.load(f)

        logger.info(f"成功从{full_path}加载token_manager对象", "TokenPersistence")
        return token_manager_obj
    except Exception as error:
        logger.error(f"加载token_manager对象失败: {str(error)}", "TokenPersistence")
        return None

def start_token_manager_persistence(token_manager_obj, interval_minutes=10):
    """
    启动定期保存token_manager的线程
    
    Args:
        token_manager_obj: 要保存的token_manager对象
        interval_minutes: 保存间隔，单位为分钟
    """
    def persistence_task():
        while True:
            # 保存token_manager对象
            save_token_manager(token_manager_obj)
            # 等待指定时间
            time.sleep(interval_minutes * 60)

    # 创建并启动线程
    persistence_thread = threading.Thread(target=persistence_task)
    persistence_thread.daemon = True
    persistence_thread.start()

    logger.info(f"token_manager持久化线程已启动，保存间隔: {interval_minutes}分钟", "TokenPersistence")

def initialization():
    # 如果成功加载，则将全局的token_manager替换为加载的对象
    global token_manager
    sso_array=[]
    sso_array_super=[]
    # 尝试从文件加载token_manager对象
    loaded_token_manager = load_token_manager()
    if loaded_token_manager:
        token_manager = loaded_token_manager
        logger.info("从文件成功恢复token_manager对象", "Server")
        
        # 从恢复的token_manager中统计令牌数量
        all_tokens = token_manager.get_all_tokens()
        normal_count = 0
        super_count = 0
        
        # 遍历token_model_map来统计不同类型的令牌
        for model_tokens in token_manager.token_model_map.values():
            for token_entry in model_tokens:
                if token_entry.get("type") == "super":
                    super_count += 1
                else:
                    normal_count += 1
        
        # 去重统计（因为同一个token可能在多个模型中）
        unique_tokens = set()
        for model_tokens in token_manager.token_model_map.values():
            for token_entry in model_tokens:
                unique_tokens.add((token_entry["token"], token_entry.get("type", "normal")))
        
        normal_count = sum(1 for _, token_type in unique_tokens if token_type == "normal")
        super_count = sum(1 for _, token_type in unique_tokens if token_type == "super")
        
        # 更新数组以便正确显示统计信息
        sso_array = ['recovered'] * normal_count  # 用占位符表示恢复的普通令牌
        sso_array_super = ['recovered'] * super_count  # 用占位符表示恢复的super令牌
        
    else:
        # 如果加载失败，则执行原有的初始化流程
        sso_array = os.environ.get("SSO", "").split(',')
        sso_array_super = os.environ.get("SSO_SUPER", "").split(',')

        combined_dict = []
        for value in sso_array_super:
            combined_dict.append({
                "token": f"sso-rw={value};sso={value}",
                "type": "super"
            })
        for value in sso_array:
            combined_dict.append({
                "token": f"sso-rw={value};sso={value}",
                "type": "normal"
            })

        logger.info("开始加载令牌", "Server")
        token_manager.load_token_status()
        token_manager.load_usage_records()  # 加载使用记录
        for tokens in combined_dict:
            if tokens:
                token_manager.add_token(tokens, True)
        token_manager.save_token_status()

    # 启动token_manager持久化定时任务
    start_token_manager_persistence(token_manager, 10)  # 每10分钟保存一次

    logger.info(f"成功加载令牌: {json.dumps(token_manager.get_all_tokens(), indent=2)}", "Server")
    logger.info(f"令牌加载完成，共加载: {len(sso_array)+len(sso_array_super)}个令牌", "Server")
    logger.info(f"其中共加载: {len(sso_array_super)}个super会员令牌", "Server")

    if CONFIG["API"]["PROXY"]:
        logger.info(f"代理已设置: {CONFIG['API']['PROXY']}", "Server")

    logger.info("初始化完成", "Server")


app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(16)
app.json.sort_keys = False

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if CONFIG["ADMIN"]["MANAGER_SWITCH"]:
        if request.method == 'POST':
            password = request.form.get('password')
            if password == CONFIG["ADMIN"]["PASSWORD"]:
                session['is_logged_in'] = True
                return redirect('/manager')
            return render_template('login.html', error=True)
        return render_template('login.html', error=False)
    else:
        return redirect('/')

def check_auth():
    return session.get('is_logged_in', False)

@app.route('/manager')
def manager():
    if not check_auth():
        return redirect('/manager/login')
    return render_template('manager.html')

@app.route('/manager/api/get')
def get_manager_tokens():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    
    # 在返回状态前，先检查并更新过期的token状态
    token_manager.check_and_reset_expired_tokens()
    return jsonify(token_manager.get_token_status_map())

@app.route('/manager/api/add', methods=['POST'])
def add_manager_token():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get('sso')
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.add_token({"token":f"sso-rw={sso};sso={sso}","type":"normal"})
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/delete', methods=['POST'])
def delete_manager_token():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        sso = request.json.get('sso')
        if not sso:
            return jsonify({"error": "SSO token is required"}), 400
        token_manager.delete_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/manager/api/cf_clearance', methods=['POST'])
def setCf_Manager_clearance():
    if not check_auth():
        return jsonify({"error": "Unauthorized"}), 401
    try:
        cf_clearance = request.json.get('cf_clearance')
        if not cf_clearance:
            return jsonify({"error": "cf_clearance is required"}), 400
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get/tokens', methods=['GET'])
def get_tokens():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法获取轮询sso令牌状态'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    
    # 在返回状态前，先检查并更新过期的token状态
    token_manager.check_and_reset_expired_tokens()
    return jsonify(token_manager.get_token_status_map())

@app.route('/add/token', methods=['POST'])
def add_token():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法添加sso令牌'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401

    try:
        sso = request.json.get('sso')
        token_manager.add_token({"token":f"sso-rw={sso};sso={sso}","type":"normal"})
        return jsonify(token_manager.get_token_status_map().get(sso, {})), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '添加sso令牌失败'}), 500

@app.route('/set/cf_clearance', methods=['POST'])
def setCf_clearance():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    try:
        cf_clearance = request.json.get('cf_clearance')
        CONFIG["SERVER"]['CF_CLEARANCE'] = cf_clearance
        return jsonify({"message": '设置cf_clearance成功'}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '设置cf_clearance失败'}), 500

@app.route('/delete/token', methods=['POST'])
def delete_token():
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if CONFIG["API"]["IS_CUSTOM_SSO"]:
        return jsonify({"error": '自定义的SSO令牌模式无法删除sso令牌'}), 403
    elif auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401

    try:
        sso = request.json.get('sso')
        token_manager.delete_token(f"sso-rw={sso};sso={sso}")
        return jsonify({"message": '删除sso令牌成功'}), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '删除sso令牌失败'}), 500

@app.route('/get/usage_statistics', methods=['GET'])
def get_usage_statistics():
    """获取token使用统计"""
    auth_token = request.headers.get('Authorization', '').replace('Bearer ', '')
    if auth_token != CONFIG["API"]["API_KEY"]:
        return jsonify({"error": 'Unauthorized'}), 401
    
    try:
        # 在返回统计前，先检查并更新过期的token状态
        token_manager.check_and_reset_expired_tokens()
        
        sso = request.args.get('sso')
        model_id = request.args.get('model')
        
        statistics = token_manager.get_usage_statistics(sso, model_id)
        
        # 添加当前时间和重置信息
        current_time = int(time.time() * 1000)
        response_data = {
            "current_time": current_time,
            "statistics": statistics,
            "token_status": token_manager.get_token_status_map(),  # 添加实时token状态
            "model_limits": {
                "grok-3": {
                    "normal": {"limit": 20, "reset_hours": 2},
                    "super": {"limit": 100, "reset_hours": 2}
                },
                "grok-3-deepsearch": {
                    "normal": {"limit": 10, "reset_hours": 2},
                    "super": {"limit": 30, "reset_hours": 2}
                },
                "grok-3-reasoning": {
                    "normal": {"limit": 10, "reset_hours": 2},
                    "super": {"limit": 30, "reset_hours": 2}
                }
            }
        }
        
        return jsonify(response_data), 200
    except Exception as error:
        logger.error(str(error), "Server")
        return jsonify({"error": '获取使用统计失败'}), 500

@app.route('/v1/models', methods=['GET'])
def get_models():
    return jsonify({
        "object": "list",
        "data": [
            {
                "id": model,
                "object": "model",
                "created": int(time.time()),
                "owned_by": "grok"
            }
            for model in CONFIG["MODELS"].keys()
        ]
    })

@app.route('/v1/chat/completions', methods=['POST'])
def chat_completions():
    response_status_code = 500
    try:
        auth_token = request.headers.get('Authorization',
                                         '').replace('Bearer ', '')
        if auth_token:
            if CONFIG["API"]["IS_CUSTOM_SSO"]:
                result = f"sso={auth_token};sso-rw={auth_token}"
                token_manager.set_token(result)
            elif auth_token != CONFIG["API"]["API_KEY"]:
                return jsonify({"error": 'Unauthorized'}), 401
        else:
            return jsonify({"error": 'API_KEY缺失'}), 401

        data = request.json
        model = data.get("model")
        stream = data.get("stream", False)

        retry_count = 0
        grok_client = GrokApiClient(model)
        request_payload = grok_client.prepare_chat_request(data)

        logger.info(json.dumps(request_payload,indent=2))

        while retry_count < CONFIG["RETRY"]["MAX_ATTEMPTS"]:
            retry_count += 1
            CONFIG["API"]["SIGNATURE_COOKIE"] = Utils.create_auth_headers(model)

            if not CONFIG["API"]["SIGNATURE_COOKIE"]:
                raise ValueError('该模型无可用令牌')

            logger.info(
                f"当前令牌: {json.dumps(CONFIG['API']['SIGNATURE_COOKIE'], indent=2)}","Server")
            logger.info(
                f"当前可用模型的全部可用数量: {json.dumps(token_manager.get_remaining_token_request_capacity(), indent=2)}","Server")

            # 获取cf_clearance值，如果已配置的为空则从文件获取
            cf_clearance_values = cf_util.get_cf_clearance_value()
            if not CONFIG['SERVER']['CF_CLEARANCE'] and cf_clearance_values:
                CONFIG['SERVER']['CF_CLEARANCE'] = cf_clearance_values[0]  # 使用第一个找到的值
            if CONFIG['SERVER']['CF_CLEARANCE']:
                CONFIG["SERVER"]['COOKIE'] = f"{CONFIG['API']['SIGNATURE_COOKIE']};{CONFIG['SERVER']['CF_CLEARANCE']}"
            else:
                CONFIG["SERVER"]['COOKIE'] = CONFIG['API']['SIGNATURE_COOKIE']
            logger.info(json.dumps(request_payload,indent=2),"Server")
            try:
                proxy_options = Utils.get_proxy_options()
                response = curl_requests.post(
                    f"{CONFIG['API']['BASE_URL']}/rest/app-chat/conversations/new",
                    headers={
                        **DEFAULT_HEADERS,
                        "Cookie":CONFIG["SERVER"]['COOKIE']
                    },
                    data=json.dumps(request_payload),
                    impersonate="chrome133a",
                    stream=True,
                    **proxy_options)
                logger.info(CONFIG["SERVER"]['COOKIE'],"Server")
                if response.status_code == 200:
                    response_status_code = 200
                    logger.info("请求成功", "Server")
                    logger.info(f"当前{model}剩余可用令牌数: {token_manager.get_token_count_for_model(model)}","Server")

                    try:
                        logger.info(f"开始处理响应 - 模型: {model}, 流式: {stream}", "Server")
                        if stream:
                            logger.info("返回流式响应", "Server")
                            return Response(stream_with_context(
                                handle_stream_response(response, model)),content_type='text/event-stream')
                        else:
                            logger.info("开始处理非流式响应", "Server")
                            content = handle_non_stream_response(response, model)
                            logger.info(f"非流式响应处理完成，内容长度: {len(str(content))}", "Server")
                            return jsonify(
                                MessageProcessor.create_chat_response(content, model))

                    except Exception as error:
                        logger.error(f"响应处理异常 - 模型: {model}, 流式: {stream}, 错误: {str(error)}", "Server")
                        logger.error(f"异常详细信息: {type(error).__name__}: {str(error)}", "Server")
                        
                        if CONFIG["API"]["IS_CUSTOM_SSO"]:
                            logger.warning(f"自定义SSO模式下的响应处理失败", "Server")
                            raise ValueError(f"自定义SSO令牌当前模型{model}的请求次数已失效")
                        
                        logger.info(f"移除失效令牌: {CONFIG['API']['SIGNATURE_COOKIE']}", "Server")
                        token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])
                        remaining_tokens = token_manager.get_token_count_for_model(model)
                        logger.info(f"移除令牌后，{model}剩余令牌数: {remaining_tokens}", "Server")
                        
                        if remaining_tokens == 0:
                            logger.error(f"模型 {model} 无可用令牌", "Server")
                            raise ValueError(f"{model} 次数已达上限，请切换其他模型或者重新对话")
                elif response.status_code == 403:
                    response_status_code = 403
                    # 记录失败的调用
                    token_manager.record_token_usage(model, CONFIG["API"]["SIGNATURE_COOKIE"], False)
                    token_manager.reduce_token_request_count(model,1)#重置去除当前因为错误未成功请求的次数，确保不会因为错误未成功请求的次数导致次数上限
                    if token_manager.get_token_count_for_model(model) == 0:
                        raise ValueError(f"{model} 次数已达上限，请切换其他模型或者重新对话")
                    print("状态码:", response.status_code)
                    print("响应头:", response.headers)
                    print("响应内容:", response.text)

                    # 删除当前使用的cf_clearance值
                    if CONFIG['SERVER']['CF_CLEARANCE']:
                        logger.info(f"检测到CF验证失败，正在删除无效的CF_CLEARANCE值: {CONFIG['SERVER']['CF_CLEARANCE']}", "Server")
                        cf_util.delete_data_by_cf_clearance(CONFIG['SERVER']['CF_CLEARANCE'])
                        # 清空当前使用的CF_CLEARANCE
                        CONFIG['SERVER']['CF_CLEARANCE'] = None

                    raise ValueError(f"IP暂时被封无法破盾，请稍后重试或者更换ip")
                elif response.status_code == 429:
                    response_status_code = 429
                    # 记录失败的调用
                    token_manager.record_token_usage(model, CONFIG["API"]["SIGNATURE_COOKIE"], False)
                    token_manager.reduce_token_request_count(model,1)
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                        raise ValueError(f"自定义SSO令牌当前模型{model}的请求次数已失效")

                    token_manager.remove_token_from_model(
                        model, CONFIG["API"]["SIGNATURE_COOKIE"])
                    if token_manager.get_token_count_for_model(model) == 0:
                        raise ValueError(f"{model} 次数已达上限，请切换其他模型或者重新对话")

                else:
                    # 记录失败的调用
                    token_manager.record_token_usage(model, CONFIG["API"]["SIGNATURE_COOKIE"], False)
                    if CONFIG["API"]["IS_CUSTOM_SSO"]:
                        raise ValueError(f"自定义SSO令牌当前模型{model}的请求次数已失效")

                    logger.error(f"令牌异常错误状态!status: {response.status_code}","Server")
                    token_manager.remove_token_from_model(model, CONFIG["API"]["SIGNATURE_COOKIE"])
                    logger.info(
                        f"当前{model}剩余可用令牌数: {token_manager.get_token_count_for_model(model)}",
                        "Server")

            except Exception as e:
                logger.error(f"请求处理异常 - 重试次数: {retry_count}, 模型: {model}, 异常类型: {type(e).__name__}, 异常信息: {str(e)}", "Server")
                logger.debug(f"异常发生时的配置状态 - 令牌: {CONFIG['API']['SIGNATURE_COOKIE'][:50] if CONFIG['API']['SIGNATURE_COOKIE'] else 'None'}..., CF_CLEARANCE: {CONFIG['SERVER']['CF_CLEARANCE'][:50] if CONFIG['SERVER']['CF_CLEARANCE'] else 'None'}...", "Server")
                
                if CONFIG["API"]["IS_CUSTOM_SSO"]:
                    logger.error("自定义SSO模式下发生异常，直接抛出", "Server")
                    raise
                    
                logger.info(f"继续重试，当前重试次数: {retry_count}/{CONFIG['RETRY']['MAX_ATTEMPTS']}", "Server")
                continue
        if response_status_code == 403:
            raise ValueError('IP暂时被封无法破盾，请稍后重试或者更换ip')
        elif response_status_code == 500:
            raise ValueError('当前模型所有令牌暂无可用，请稍后重试')

    except Exception as error:
        logger.error(f"聊天API最终异常 - 模型: {data.get('model', 'unknown') if 'data' in locals() else 'unknown'}, 状态码: {response_status_code}, 异常类型: {type(error).__name__}, 异常信息: {str(error)}", "ChatAPI")
        
        # 记录请求的基本信息用于调试
        try:
            if 'data' in locals():
                logger.debug(f"请求详情 - 模型: {data.get('model')}, 消息数量: {len(data.get('messages', []))}, 流式: {data.get('stream', False)}", "ChatAPI")
            if 'model' in locals():
                remaining_capacity = token_manager.get_remaining_token_request_capacity()
                logger.debug(f"当前令牌容量状态: {json.dumps(remaining_capacity, indent=2)}", "ChatAPI")
        except Exception as debug_error:
            logger.warning(f"记录调试信息时出错: {str(debug_error)}", "ChatAPI")
        
        return jsonify(
            {"error": {
                "message": str(error),
                "type": "server_error",
                "timestamp": int(time.time())
            }}), response_status_code

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    return 'api运行正常', 200








# 日志配置已在上方的Logger类中定义



# 初始化Faker
fake = Faker()

# 默认管理员密码，如果环境变量未设置则使用此密码
DEFAULT_ADMIN_PASSWORD = "123456"

# 读取管理员密码环境变量
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)
logger.info(f"当前使用的管理员密码来源: {'环境变量' if ADMIN_PASSWORD != DEFAULT_ADMIN_PASSWORD else '默认值'}")

# 生成cf值的数量
DEFAULT_CF_CLEARANCE_SIZE = 1
CF_CLEARANCE_SIZE = os.environ.get("CF_CLEARANCE_SIZE", DEFAULT_CF_CLEARANCE_SIZE)
logger.info(
    f"当前配置中需要生成CF值的数量: {'环境变量' if CF_CLEARANCE_SIZE != DEFAULT_CF_CLEARANCE_SIZE else '默认值'}")

# 存储配置和数据的文件路径
CONFIG_FILE = "data/cf_config.json"
COOKIES_FILE = "data/cf_cookies.json"  # 保留用于兼容性，实际数据会同时存储在CONFIG_FILE中

# 默认配置
DEFAULT_CONFIG = {
    "url": "https://grok.com",
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

    def to_dict(self):
        """兼容不同版本的Pydantic，返回模型的字典表示"""
        # 尝试使用 model_dump (Pydantic v2+)
        if hasattr(self, "model_dump"):
            return self.model_dump()
        # 回退到 dict (Pydantic v1)
        return self.dict()


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


def generate_random_user_agents(count=1):
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


@app.route("/api/get-cf-list", methods=['GET'])
def get_cf_list():
    """获取需要更新的代理和用户代理列表"""
    logger.info(f"收到获取配置请求")
    
    # 从请求参数中获取密码
    admin_password = request.args.get('admin_password')
    
    if admin_password:
        logger.info(f"提供的admin_password长度: {len(admin_password)}")
    else:
        logger.warning("请求中没有提供admin_password参数")

    # 验证密码
    if admin_password != DEFAULT_ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 接收到的密码与默认密码不匹配")
        logger.info(f"接收到的密码: {admin_password}, 默认密码: {DEFAULT_ADMIN_PASSWORD}")
        return jsonify({"error": "Invalid admin password"}), 403

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

    logger.info(
        f"返回配置信息: url={response_data['url']}, need_update.proxy_url_pool数量={len(need_update['proxy_url_pool'])}, need_update.user_agent_list数量={len(need_update['user_agent_list'])}")

    return response_data


@app.route('/api/set-cf-cookie', methods=['POST'])
def set_cf_cookie():
    """设置新的Cloudflare cookie"""
    logger.info(f"收到设置Cookie请求")
    
    # 从请求参数中获取密码
    admin_password = request.args.get('admin_password', '')
    
    if admin_password:
        logger.info(f"提供的admin_password长度: {len(admin_password)}")
    else:
        logger.warning("请求中没有提供admin_password参数")

    # 验证密码
    if admin_password != DEFAULT_ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 接收到的密码与默认密码不匹配")
        logger.info(f"接收到的密码: {admin_password}, 默认密码: {DEFAULT_ADMIN_PASSWORD}")
        return jsonify({"error": "Invalid admin password"}), 403
        
    # 从请求中获取cookie数据
    try:
        cookie_data = request.get_json()
        
        # 加载当前配置和Cookie列表
        config = load_config()
        cookies = config.get("exist_data_list", [])
        
        # 检查是否已存在相同条件的cookie
        found = False
        for i, cookie in enumerate(cookies):
            need_update = False
        
            # 检查是否是相同条件的cookie
            if cookie_data.get("proxy_url") is not None:
                if (cookie.get("proxy_url") == cookie_data.get("proxy_url") and
                        cookie.get("user_agent") == cookie_data.get("user_agent")):
                    found = True
                    need_update = True
            else:
                if (cookie.get("proxy_url") is None and
                        cookie.get("user_agent") == cookie_data.get("user_agent")):
                    found = True
                    need_update = True
        
            if need_update:
                # 更新cookie
                cookies[i] = cookie_data
                break
        
        if not found:
            # 添加新cookie
            cookies.append(cookie_data)
        
        # 更新配置文件中的exist_data_list
        config["exist_data_list"] = cookies
        save_config(config)
        
        # 为了兼容性，也保存到cookies文件
        save_cookies(cookies)
        
        logger.info(
            f"成功保存Cookie: user_agent={cookie_data.get('user_agent')[:50]}...")
        
        return jsonify({"status": "success", "message": "Cookie saved successfully"})
    except Exception as e:
        logger.error(f"处理Cookie数据失败: {str(e)}")
        return jsonify({"status": "error", "message": f"处理Cookie数据失败: {str(e)}"}), 400


@app.route("/api/update-config", methods=['POST'])
def update_config():
    """更新配置"""
    logger.info(f"收到更新配置请求")
    
    # 从请求参数中获取密码
    admin_password = request.args.get('admin_password')
    
    if admin_password:
        logger.info(f"提供的admin_password长度: {len(admin_password)}")
    else:
        logger.warning("请求中没有提供admin_password参数")

    # 验证密码
    if admin_password != DEFAULT_ADMIN_PASSWORD:
        logger.warning(f"管理员密码验证失败: 接收到的密码与默认密码不匹配")
        logger.info(f"接收到的密码: {admin_password}, 默认密码: {DEFAULT_ADMIN_PASSWORD}")
        return jsonify({"error": "Invalid admin password"}), 403

    try:
        config_data = request.get_json()
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

        return jsonify({"status": "success", "message": "Config updated successfully"})
    except Exception as e:
        logger.error(f"更新配置失败: {str(e)}")
        return jsonify({"status": "error", "message": f"更新配置失败: {str(e)}"}), 400


@app.get("/api/debug")
def debug_info():
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

if __name__ == '__main__':

    logger.info(f"管理员密码来源: {'环境变量' if ADMIN_PASSWORD != DEFAULT_ADMIN_PASSWORD else '默认值'}")

    token_manager = AuthTokenManager()
    initialization()

    app.run(
        host='0.0.0.0',
        port=CONFIG["SERVER"]["PORT"],
        debug=False
    )

