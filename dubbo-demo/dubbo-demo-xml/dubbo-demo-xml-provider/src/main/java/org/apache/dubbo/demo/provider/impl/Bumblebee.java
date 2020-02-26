package org.apache.dubbo.demo.provider.impl;

import org.apache.dubbo.demo.provider.Robot;

/**
 * @author zhangzhida
 * @date 2019/9/24
 */
public class Bumblebee implements Robot {

    @Override
    public void sayHello() {
        System.out.println("Hello, I am Bumblebee.");
    }
}
