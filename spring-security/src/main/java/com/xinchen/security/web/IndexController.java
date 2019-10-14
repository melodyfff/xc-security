package com.xinchen.security.web;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author xinchen
 * @version 1.0
 * @date 14/10/2019 15:27
 */
@RestController
public class IndexController {
    @GetMapping("/")
    public String hello(){
        return "hello";
    }

    @GetMapping("/success")
    public String loginSuccess(){
        return "login Success!";
    }

    @GetMapping("/out")
    public String loginOut(){
        return "login out!";
    }
}
