package com.ljm.nginx.guard.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @author Dominick Li
 * @CreateTime 2021/1/12 17:27
 * @description
 **/
public class NginxUtil {


    private NginxUtil() {
    }

    private final static Logger logger = LoggerFactory.getLogger(NginxUtil.class);

    /**
     * 自定义匹配恶意攻击的信息
     */
    private static List<String> MATCHER_LIST;

    public static void setMatcherList(List<String> matcherList) {
        MATCHER_LIST = matcherList;
    }

    /**
     * 换行符
     */
    private static String lineSeparator = "\r\n";

    /**
     * 日期格式
     */
    private final static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy_MM_dd_HH_ss");


    /**
     * 扫描黑名单
     *
     * @param logPath       access.log文件的路径
     * @param blackListPath 黑名单配置文件路径
     * @param binPath       nginx的启动文件路径
     * @throws Exception
     */
    public static void scanningBlackList(String logPath, String blackListPath, String binPath) throws Exception {
        //第一步 找到非法访问IP
        Set<String> set = NginxUtil.readNginxAccess(logPath);
        if (set != null && set.size() > 0) {
            //第二步,写入非法IP进nginx的blackList文件
            boolean flag = NginxUtil.writeBlacklist(blackListPath, set);
            //第三步,备份之前的access.log,刷新nginx配置使黑名单生效
            if (flag) {
                //备份nginx日志文件
                String backUpLogPath = logPath + "_backup_" + simpleDateFormat.format(new Date());
                Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", String.format("mv %s %s", logPath, backUpLogPath)}, null, null);
                process.waitFor();
                //执行 /usr/local/nginx/nginx -s reload 会重新生成一个新的access.log文件
                process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", String.format("%s -s reload", binPath)}, null, null);
                process.waitFor();
            }
        }
    }

    /**
     * 解析nginx日志中的非法访问的IP地址
     * @param logPath
     * @return 非法IP地址
     * @throws Exception
     */
    private static Set<String> readNginxAccess(String logPath) throws Exception {
        File file = new File(logPath);
        if (!file.exists()) {
            logger.error("{} not exists", logPath);
            return null;
        }

        Set<String> set = new HashSet<>();
        InputStreamReader ir = new InputStreamReader(new FileInputStream(file));
        LineNumberReader input = new LineNumberReader(ir);
        String line;

        //是否匹配
        boolean match;
        String ip;
        while ((line = input.readLine()) != null) {
            final String fLine = line;
            match = false;
            for (String str : MATCHER_LIST) {
                //如果匹配上了,把ip加入set集合并结束for循环
                if (fLine.contains(str)) {
                    System.out.println(fLine);
                    set.add(fLine.split(" ")[0]);
                    match = true;
                    break;
                }
            }
            if (!match && StringUtils.hasLength(line)) {
                //如果不是恶意攻击IP,判断下是否是国外Ip
                ip = fLine.split(" ")[0];
                if(!"127.0.0.1".equals(ip)){
                    match = IpFromUtils.isChina(fLine.split(" ")[0]);
                    if (!match) {
                        //非中国IP访问
                        set.add(ip);
                    }
                }
            }
        }
        return set;
    }


    /**
     * 写入黑名单列表
     *
     * @param blackListConfigPath 黑名单配置文件路径
     * @param blackListSet        扫描出来的黑客ip集合
     * @return (如果扫描出来的黑客IP地址和已存在的不完全重叠, 返回true, 否则false)
     * @throws Exception
     */
    private static boolean writeBlacklist(String blackListConfigPath, Set<String> blackListSet) throws Exception {
        File file = new File(blackListConfigPath);
        if (!file.exists()) {
            file.createNewFile();
        }
        List<String> list = new ArrayList<>();
        InputStreamReader ir = new InputStreamReader(new FileInputStream(file));
        LineNumberReader input = new LineNumberReader(ir);
        String line;
        String ip;
        while ((line = input.readLine()) != null) {
            if ("".equals(line.trim()) || line.startsWith("#")) {
                continue;
            }
            ip = line.split(" ")[1];
            ip = ip.substring(0, ip.length() - 1);
            list.add(ip);
        }
        //遍历添加黑名单列表中不存在的IP
        Set<String> filterSet = new HashSet();
        blackListSet.forEach(ipaddr -> {
            if (!list.contains(ipaddr)) {
                filterSet.add(ipaddr);
            }
        });
        if (filterSet.size() > 0) {
            FileWriter out = new FileWriter(file, true);
            BufferedWriter bw = new BufferedWriter(out);
            for (String ipaddr : filterSet) {
                bw.write(lineSeparator);
                bw.write(String.format("deny %s;", ipaddr));
                logger.info("黑客IP:{} 已写入nginx黑名单列表", ipaddr);
            }
            //写入文件修改时间
            bw.write(lineSeparator);
            bw.write("#" + simpleDateFormat.format(new Date()));
            bw.flush();
            bw.close();
            return true;
        } else {
            logger.info("未发现新的黑客IP地址");
            return false;
        }
    }


    /**
     * 监测nginx进程是否存活
     */
    public static void monitor(String bin, String pingPort) {
        try {
            //执行 curl访问nginx启动的某个端口,如果不存在则表示nginx已经挂了
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "curl " + pingPort}, null, null);
            InputStreamReader isr = new InputStreamReader(process.getErrorStream());
            BufferedReader br = new BufferedReader(isr);
            String line;
            StringBuilder sb = new StringBuilder();
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            process.waitFor();
            String res = sb.toString();
            if (StringUtils.hasLength(res) && res.contains("Connection refused")) {
                logger.info("nginx process abnormal，restart ....");
                process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", bin}, null, null);
                process.waitFor();
            } else {
                logger.info("nginx process normal");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) throws Exception {
        //nginx的工作空间
        String nginxPath = "/usr/local/nginx/";
        //nging的access.log路径
        String logPath = nginxPath + "logs/access.log";
        //黑名单配置文件路径
        String blackListPath = nginxPath + "conf/blackListIp.conf";
        //启动脚本文件路径
        String binPath = nginxPath + "bin/nginx";
        ScheduledExecutorService scheduledThreadPool = Executors.newSingleThreadScheduledExecutor();
        //30秒执行一次
        scheduledThreadPool.scheduleAtFixedRate(() -> {
            try {
                scanningBlackList(logPath, blackListPath, binPath);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }, 0, 30, TimeUnit.SECONDS);
    }


//    public static void main(String[] args) throws Exception {
//        String nginxPath = "D:\\Public_fbs\\nginx-1.17.9\\";
//        String logPath = nginxPath + "logs\\access.log";
//        String blackListPath = nginxPath + "conf\\blackListIp.conf";
//        String binPath = nginxPath + "bin\\nginx.exe";
//        scanningBlackList(logPath, blackListPath, binPath);
//    }
}
