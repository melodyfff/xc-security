package com.xinchen.security.web;

import com.xinchen.security.core.vo.Response;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;


/**
 *
 * 登录相关
 *
 * @author xinchen
 * @version 1.0
 * @date 15/10/2019 14:58
 */
@RestController
public class LoginController {

    @GetMapping(value = "/login/success")
    public ResponseEntity loginSuccess(){
        return ResponseEntity.accepted().body(new Response("login success"));
    }

    @PostMapping(value = "/login/fail")
    public ResponseEntity loginFail(HttpServletRequest request){
        return ResponseEntity.badRequest().body(new Response("login fail! "+request.getAttribute("SPRING_SECURITY_LAST_EXCEPTION")));
    }

    @GetMapping(value = "/logout/success")
    public ResponseEntity logout(){
        return ResponseEntity.badRequest().body(new Response("logout! "));
    }
}
