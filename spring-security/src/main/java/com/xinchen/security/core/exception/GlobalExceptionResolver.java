package com.xinchen.security.core.exception;

import com.xinchen.security.core.vo.Response;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.support.DefaultHandlerExceptionResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 *
 * 全局统一异常处理
 *
 * @author xinchen
 * @version 1.0
 * @date 15/10/2019 15:26
 */
@RestControllerAdvice(basePackages = "com.xinchen.security")
@Slf4j
public class GlobalExceptionResolver extends DefaultHandlerExceptionResolver {

    @ExceptionHandler(Exception.class)
    public ResponseEntity throwableHandler(HttpServletRequest request, HttpServletResponse response, Throwable ex){
        log.error("ERROR: ",ex);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new Response(ex.getMessage()));
    }
}
