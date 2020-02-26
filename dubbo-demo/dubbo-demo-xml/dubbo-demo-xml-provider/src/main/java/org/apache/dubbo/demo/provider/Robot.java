package org.apache.dubbo.demo.provider;

import org.apache.dubbo.common.extension.ExtensionLoader;
import org.apache.dubbo.common.extension.SPI;

/**
 * @author zhangzhida
 * @date 2019/9/24
 */
@SPI
public interface Robot {
    void sayHello();
}

class JavaSPITest {
    public static void main(String[] args) {
        ExtensionLoader<Robot> extensionLoader =
                ExtensionLoader.getExtensionLoader(Robot.class);
        Robot optimus= extensionLoader.getExtension("optimusPrime");
        optimus.sayHello();
        Robot bumblebee = extensionLoader.getExtension("bumblebee");
        bumblebee.sayHello();
    }
}