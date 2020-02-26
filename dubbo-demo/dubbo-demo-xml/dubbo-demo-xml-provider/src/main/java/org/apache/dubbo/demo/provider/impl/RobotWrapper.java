package org.apache.dubbo.demo.provider.impl;

import org.apache.dubbo.demo.provider.Robot;

/**
 * aop
 * 创建的时候会先创建 robot 的扩展实现类
 * 最后回把当前的RobotWrapper对象作为 robot 拓展类的包装类返回
 * 实际调用时就会先调用 RobotWrapper sayHello 在调用 具体实现类的 sayHello 做到aop的功能
 * 原理  org.apache.dubbo.common.extension.ExtensionLoader#createExtension(java.lang.String) 方法
 *
 * @author zhangzhida
 * @date 2019/9/25
 */
public class RobotWrapper implements Robot {

    private Robot robot;

    public RobotWrapper(Robot robot) {
        this.robot = robot;

    }

    @Override
    public void sayHello() {
        System.out.println("before");
        robot.sayHello();
        System.out.println("after");
    }
}
