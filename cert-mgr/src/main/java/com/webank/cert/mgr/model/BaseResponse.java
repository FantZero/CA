package com.webank.cert.mgr.model;

import lombok.Data;

/**
 * @author aaronchu
 */
@Data
public class BaseResponse<T> {

    private String code;

    private String message;

    private T body;

    public BaseResponse() {}

    public BaseResponse(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public BaseResponse(String code, String message, T obj) {
        this.code = code;
        this.message = message;
        this.body = obj;
    }

    /**
     * 操作成功
     * @param message 返回信息
     * @return BaseResponse
     */
    public static <T> BaseResponse<T> success(String message) {
        return new BaseResponse<T>("0", message);
    }


    public static <T> BaseResponse<T> success() {
        return new BaseResponse<T>("0", "响应成功");
    }

    public static <T> BaseResponse<T> success(T body) {
        return new BaseResponse<T>("0", "响应成功", body);
    }

    /**
     * 操作成功，并返回数据
     * @param message 返回信息
     * @param body 返回数据
     * @return BaseResponse
     */
    public static <T> BaseResponse<T> success(String message, T body) {
        return new BaseResponse<T>("0", message, body);
    }

    /**
     * 操作失败，返回错误码和信息
     * @param code 错误码
     * @param message 错误信息
     * @return BaseResponse
     */
    public static <T> BaseResponse<T> error(String code, String message ) {
        return new BaseResponse<T>(code, message);
    }

    /**
     *
     * 操作失败，返回错误码和信息
     * @param code 错误码
     * @param message 错误信息
     * @param body 错误数据
     * @return BaseResponse
     */
    public static <T> BaseResponse<T> error(String code, String message, T body ) {
        return new BaseResponse<T>(code, message, body);
    }
}
