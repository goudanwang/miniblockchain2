# 使用Python 3.9官方镜像作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=pos_blockchain_ctf.py
ENV FLASK_ENV=production

# 复制requirements.txt并安装依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY *.py .
COPY *.md .

# 创建必要的目录和文件
RUN mkdir -p /app/logs

# 暴露端口5001
EXPOSE 5001

# 创建非root用户运行应用（安全最佳实践）
RUN useradd -m -u 1000 ctfuser && chown -R ctfuser:ctfuser /app
USER ctfuser

# 启动命令
CMD ["python", "pos_blockchain_ctf.py"]
