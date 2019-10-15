package com.xinchen.security.core.vo;

import lombok.Data;
import lombok.EqualsAndHashCode;

/**
 * @author xinchen
 * @version 1.0
 * @date 15/10/2019 17:14
 */
@EqualsAndHashCode(callSuper = true)
@Data
public class ErrorResponse extends Response{
    private Exception exception;


    public ErrorResponse(String data,Exception exception) {
        super(data);
        this.exception = exception;
    }
}
