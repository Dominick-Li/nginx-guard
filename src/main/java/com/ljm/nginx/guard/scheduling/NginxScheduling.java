package com.ljm.nginx.guard.scheduling;

import com.ljm.nginx.guard.config.NginxParam;
import com.ljm.nginx.guard.util.NginxUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;


/**
 * @author Dominick Li
 * @CreateTime 2021/1/12 18:44
 * @description
 **/
@Component
public class NginxScheduling {

    @Autowired
    NginxParam nginxParam;

    /**
     * 扫描非法IP
     * 每隔30秒扫描一次非法IP并加入黑名单
     */
    @Scheduled(fixedDelay = 30000)
    public void scanForIllegalIP() throws Exception {
        NginxUtil.scanningBlackList(nginxParam.getLog(), nginxParam.getBlackListIp(), nginxParam.getSbin());
    }

    /**
     * bean加载的时候执行的初始化操作
     */
    @PostConstruct
    public void init() {
        NginxUtil.setMatcherList(nginxParam.getMatcherList());
    }

    /**
     * 健康监测
     * @throws Exception
     */
    @Scheduled(fixedDelay = 60000)
    public void healthMonitoring()  {
        NginxUtil.monitor(nginxParam.getSbin(),nginxParam.getPingPort());
    }

}
