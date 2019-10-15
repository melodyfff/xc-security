package com.xinchen.security.web;

import com.xinchen.security.core.vo.Response;
import org.springframework.http.ResponseEntity;
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
    public ResponseEntity hello(){
        return ResponseEntity.ok(new Response("hello"));
    }
}
