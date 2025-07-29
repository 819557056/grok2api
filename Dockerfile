FROM python:3.9-slim

WORKDIR /app

# 创建必要的目录
RUN mkdir -p /app/data

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装Python包
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用文件
COPY app.py .
COPY cf_util.py .
#COPY templates/* ./templates/

# 复制环境变量文件（如果存在）
COPY .env* ./

# 复制数据文件（如果存在）
#COPY data/ ./data/

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["python", "app.py"]
