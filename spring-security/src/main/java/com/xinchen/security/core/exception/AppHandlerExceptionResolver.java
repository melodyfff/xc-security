package com.xinchen.security.core.exception;

import com.alibaba.fastjson.JSON;
import com.xinchen.security.core.vo.ErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.AbstractHandlerExceptionResolver;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 *
 * 全局统一异常处理
 *
 * @author xinchen
 * @version 1.0
 * @date 15/10/2019 16:56
 */
@Slf4j
public class AppHandlerExceptionResolver extends AbstractHandlerExceptionResolver {
    public AppHandlerExceptionResolver() {
        setOrder(1);
        setWarnLogCategory(getClass().getName());
    }

    @Override
    protected ModelAndView doResolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception ex) {
        if (null != ex) {
            log.error("AppHandlerExceptionResolver ERROR: ", ex);
            response.setCharacterEncoding("utf-8");
            response.setContentType("application/json; charset=utf-8");
            try {
                // 全部转换为json
                response.getWriter().write(JSON.toJSONString(new ErrorResponse(ex.getMessage(),ex)));
            } catch (IOException e) {
                log.error("",e);
            }
        }
        return null;
    }

}
