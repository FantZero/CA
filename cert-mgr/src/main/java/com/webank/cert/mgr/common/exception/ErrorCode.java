package com.webank.cert.mgr.common.exception;

/**
 * @author Whty
 */
public enum ErrorCode {


    SYSTEM_ERROR("10000", "系统错误，请联系管理员"),

    PARAM_CHECK_ERROR("14000", "参数检错误"),

    METHOD_NOT_ALLOWED_ERROR("14050", "不支持当前请求方法类型"),

    MEDIA_TYPE_ERROR("14150", "不支持的媒体类型"),

    FILE_UPLOAD_FAILED("12024","文件上传失败！"),

    IP_NOT_EXISTS("12025","连接失败，请检查网络设置！"),

    FILE_NOT_EXISTS("12026","文件不存在！");

    private String code;
    private String message;

    ErrorCode(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return this.code;
    }

    public String getMessage() {
        return this.message;
    }


}
