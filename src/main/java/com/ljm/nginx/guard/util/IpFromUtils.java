package com.ljm.nginx.guard.util;

import lombok.extern.slf4j.Slf4j;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

/**
 * @author Dominick Li
 * @CreateTime 2021/4/16 11:20
 * @description
 **/
@Slf4j
public class IpFromUtils {

    private final static String[] privinces = {"北京市", "天津市", "河北省", "山西省", "内蒙古", "辽宁省", "吉林省", "黑龙江省", "上海市", "江苏省", "浙江省", "安徽省", "福建省", "江西省", "山东省", "河南省", "湖北省", "湖南省", "广东省", "广西", "海南省", "重庆市", "四川省", "贵州省", "云南省", "西藏", "陕西省", "甘肃省", "青海省", "宁夏", "新疆", "台湾省", "香港", "澳门"};

    private static String getAddressByIp(String ip) {
        try {
            URL url = new URL("http://opendata.baidu.com/api.php?query=" + ip + "&co=&resource_id=6006&t=1433920989928&ie=utf8&oe=utf-8&format=json");
            URLConnection conn = url.openConnection();
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), "utf-8"));
            String line = null;
            StringBuffer result = new StringBuffer();
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
            reader.close();
            JSONObject jsStr = new JSONObject(result.toString());
            JSONArray jsData = (JSONArray) jsStr.get("data");
            JSONObject data = (JSONObject) jsData.get(0);//位置
            return (String) data.get("location");
        } catch (IOException e) {
            log.error("getAddressByIp error, ip={},msg={}",ip,e);
            return  null;
        }
    }


    public static boolean isChina(String ip) {
        String address = getAddressByIp(ip);
        if(address==null){
            //获取Ip异常的情况
            return true;
        }
        boolean china = false;
        for (String privince : privinces) {
            if (address.startsWith(privince)) {
                china = true;
                break;
            }
        }
        if(!china){
            log.error("ip:{},address:{}",ip,address);
        }
        return china;
    }

}
