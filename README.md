# 程序的作用
## 1.根据攻击的内容信息把ip加入nginx的黑名单列表
## 2.判断ip是否为国外网站,如果是国外的ip访问也加入黑名单
## 3.根据提供的端口监听nginx进程是否存再,如果不存在,则重启nginx进程

# 使用手册

## 1. 在nginx的配置文件中引入ip黑名单文件
我的安装路径是/usr/local/nginx/,根据你们自己的安装路径自行修改
```
#创建黑名单配置文件
mkdir /usr/local/nginx/conf/blackListIp.conf
# 修改nginx.conf文件，在http标签下引入blackListIp.conf文件
vi /usr/local/nginx/conf/nginx.conf
http {
 include blackListIp.conf;#添加当前行
}
```

## 2.修改应用的application.yml
如果nginx安装路径是/usr/local/nginx/,则只需要修改pingPort属性即可

属性 | 描述
--- | ---
workspace | nginx的安装路径
sbin | 启动脚本路径
log | access.log文件的路径
blackListIp | 黑名单IP存储文件
pingPort | 监控nginx使用的端口

## 3.运行程序
- 1 mvn clean install
- 2 上传release目录到服务器上面
- 3 cd release/bin 目录下
- 4 chmod 755 server.sh
- 5 ./server.sh start